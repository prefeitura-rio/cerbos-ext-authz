package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prefeitura-rio/cerbos-ext-authz/internal/config"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/service"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	authorizationHeader = "authorization"
	targetServiceHeader = "x-target-service"
	resultHeader        = "x-ext-authz-check-result"
	receivedHeader      = "x-ext-authz-check-received"
	resultAllowed       = "allowed"
	resultDenied        = "denied"
)

var (
	httpPort = flag.String("http", "8000", "HTTP server port")
	grpcPort = flag.String("grpc", "9000", "gRPC server port")
	denyBody = "denied by ext_authz: authorization failed"
)

// stripQueryParams removes query parameters from a path
// Example: "/api/users?id=123&name=test" -> "/api/users"
func stripQueryParams(path string) string {
	if idx := strings.Index(path, "?"); idx != -1 {
		return path[:idx]
	}
	return path
}

// ExtAuthzServer implements the ext_authz v3 gRPC and HTTP check request API.
type ExtAuthzServer struct {
	grpcServer *grpc.Server
	httpServer *http.Server
	service    *service.Service
	// For test only
	httpPort chan int
	grpcPort chan int
}

func (s *ExtAuthzServer) logRequest(allow string, request *authv3.CheckRequest) {
	httpAttrs := request.GetAttributes().GetRequest().GetHttp()
	log.Printf("[gRPCv3][%s]: %s%s, attributes: %v\n", allow, httpAttrs.GetHost(),
		httpAttrs.GetPath(),
		request.GetAttributes())
}

func (s *ExtAuthzServer) allow(request *authv3.CheckRequest) *authv3.CheckResponse {
	s.logRequest("allowed", request)
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultAllowed,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: returnIfNotTooLong(request.GetAttributes().String()),
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func (s *ExtAuthzServer) allowWithDetails(request *authv3.CheckRequest, authResponse *service.AuthorizationResponse) *authv3.CheckResponse {
	s.logRequest("allowed", request)

	headers := []*corev3.HeaderValueOption{
		{
			Header: &corev3.HeaderValue{
				Key:   resultHeader,
				Value: resultAllowed,
			},
		},
		{
			Header: &corev3.HeaderValue{
				Key:   receivedHeader,
				Value: returnIfNotTooLong(request.GetAttributes().String()),
			},
		},
	}

	// Add Cerbos-specific headers
	if authResponse.Action != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Action",
				Value: authResponse.Action,
			},
		})
	}

	if authResponse.PrincipalID != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Principal",
				Value: authResponse.PrincipalID,
			},
		})
	}

	if authResponse.Cache != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Cache",
				Value: authResponse.Cache,
			},
		})
	}

	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: headers,
			},
		},
		Status: &status.Status{Code: int32(codes.OK)},
	}
}

func (s *ExtAuthzServer) deny(request *authv3.CheckRequest) *authv3.CheckResponse {
	s.logRequest("denied", request)
	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   denyBody,
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   resultHeader,
							Value: resultDenied,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   receivedHeader,
							Value: returnIfNotTooLong(request.GetAttributes().String()),
						},
					},
				},
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

func (s *ExtAuthzServer) denyWithDetails(request *authv3.CheckRequest, authResponse *service.AuthorizationResponse) *authv3.CheckResponse {
	s.logRequest("denied", request)

	// Create headers with detailed information
	headers := []*corev3.HeaderValueOption{
		{
			Header: &corev3.HeaderValue{
				Key:   resultHeader,
				Value: resultDenied,
			},
		},
		{
			Header: &corev3.HeaderValue{
				Key:   receivedHeader,
				Value: returnIfNotTooLong(request.GetAttributes().String()),
			},
		},
		{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Status",
				Value: authResponse.Status,
			},
		},
	}

	// Add optional headers if present
	if authResponse.Action != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Action",
				Value: authResponse.Action,
			},
		})
	}

	if authResponse.PrincipalID != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Principal",
				Value: authResponse.PrincipalID,
			},
		})
	}

	if authResponse.Cache != "" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Cache",
				Value: authResponse.Cache,
			},
		})
	}

	// Add service health information for degraded states
	if authResponse.Status == "degraded" || authResponse.Status == "circuit_breaker_open" {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Service-Health",
				Value: "degraded",
			},
		})
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Circuit-Breaker-State",
				Value: s.service.GetCircuitBreakerState(),
			},
		})
	} else {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   "X-Cerbos-Service-Health",
				Value: "healthy",
			},
		})
	}

	// Provide error message based on status
	var errorMessage string
	if authResponse.Reason != "" {
		errorMessage = fmt.Sprintf("denied by ext_authz: %s", authResponse.Reason)
	} else {
		switch authResponse.Status {
		case "invalid_token":
			errorMessage = "denied by ext_authz: invalid or expired JWT token"
		case "degraded":
			errorMessage = "denied by ext_authz: service degraded, authorization failed"
		case "circuit_breaker_open":
			errorMessage = "denied by ext_authz: service temporarily unavailable"
		case "error":
			errorMessage = "denied by ext_authz: authorization service error"
		default:
			errorMessage = fmt.Sprintf("denied by ext_authz: %s", authResponse.Status)
		}
	}

	return &authv3.CheckResponse{
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:    errorMessage,
				Headers: headers,
			},
		},
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
	}
}

// Check implements gRPC v3 check request.
func (s *ExtAuthzServer) Check(ctx context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attrs := request.GetAttributes()
	httpAttrs := attrs.GetRequest().GetHttp()

	// Allow OPTIONS requests (CORS preflight) without requiring authorization
	if httpAttrs.GetMethod() == "OPTIONS" {
		return s.allow(request), nil
	}

	// Extract request details
	headers := httpAttrs.GetHeaders()
	method := httpAttrs.GetMethod()
	host := ""
	if headers != nil {
		host = headers["host"]
	}

	// Extract path from X-Envoy-Original-Path header
	path := ""
	if headers != nil {
		if originalPath, exists := headers["x-envoy-original-path"]; exists {
			// Strip query parameters for mapping lookup
			path = stripQueryParams(originalPath)
		}
	}

	// If X-Envoy-Original-Path header is missing, deny the request
	if path == "" {
		log.Printf("[gRPC][denied]: Missing X-Envoy-Original-Path header")
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.InvalidArgument)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_BadRequest},
					Body:   "Missing X-Envoy-Original-Path header - path information required for authorization",
					Headers: []*corev3.HeaderValueOption{
						{
							Header: &corev3.HeaderValue{
								Key:   "X-Cerbos-Error",
								Value: "missing_original_path_header",
							},
						},
					},
				},
			},
		}, nil
	}

	// Debug logging: Log ALL headers
	log.Printf("[DEBUG] gRPC Request - Method: %s, Path: %s, Host: %s", method, path, host)
	log.Printf("[DEBUG] All Headers: %+v", headers)

	// Extract authorization header
	authHeader := ""
	if headers != nil {
		if auth, exists := headers[authorizationHeader]; exists {
			authHeader = auth
		} else if auth, exists := headers["Authorization"]; exists {
			authHeader = auth
		}
	}

	// Extract target service hint
	targetService := ""
	if headers != nil {
		if svc, exists := headers[targetServiceHeader]; exists {
			targetService = svc
		}
	}

	// Create authorization request
	authReq := &service.AuthorizationRequest{
		AuthHeader: authHeader,
		Service:    targetService,
		Path:       path,
		Method:     method,
		Host:       host,
	}

	// Call our service to perform authorization
	response, err := s.service.Authorize(ctx, authReq)
	if err != nil {
		log.Printf("Authorization error: %v", err)
		return s.deny(request), nil
	}

	// Return allow/deny based on service response
	if response.Allowed {
		return s.allowWithDetails(request, response), nil
	}

	// Create a custom deny response with detailed information
	return s.denyWithDetails(request, response), nil
}

// ServeHTTP implements the HTTP check request.
func (s *ExtAuthzServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("[HTTP] read body failed: %v", err)
	}

	l := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, returnIfNotTooLong(string(body)))

	// Debug logging: Log ALL headers for HTTP requests
	log.Printf("[DEBUG] HTTP Request - Method: %s, Path: %s, Host: %s", request.Method, request.URL.Path, request.Host)
	log.Printf("[DEBUG] All HTTP Headers: %+v", request.Header)

	// Allow OPTIONS requests (CORS preflight) without requiring authorization
	if request.Method == "OPTIONS" {
		log.Printf("[HTTP][allowed]: %s", l)
		response.Header().Set(resultHeader, resultAllowed)
		response.Header().Set(receivedHeader, l)
		response.WriteHeader(http.StatusOK)
		return
	}

	// Extract authorization header
	authHeader := request.Header.Get(authorizationHeader)
	if authHeader == "" {
		authHeader = request.Header.Get("Authorization")
	}

	// Extract target service hint
	targetService := request.Header.Get(targetServiceHeader)

	// Extract path from X-Envoy-Original-Path header
	originalPath := request.Header.Get("X-Envoy-Original-Path")
	if originalPath == "" {
		log.Printf("[HTTP][denied]: Missing X-Envoy-Original-Path header")
		response.Header().Set("X-Cerbos-Error", "missing_original_path_header")
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte("Missing X-Envoy-Original-Path header - path information required for authorization"))
		return
	}

	// Strip query parameters for mapping lookup
	path := stripQueryParams(originalPath)

	// Create authorization request
	authReq := &service.AuthorizationRequest{
		AuthHeader: authHeader,
		Service:    targetService,
		Path:       path,
		Method:     request.Method,
		Host:       request.Host,
	}

	// Call our service to perform authorization
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authResponse, err := s.service.Authorize(ctx, authReq)
	if err != nil {
		log.Printf("[HTTP] authorization error: %v", err)
		response.Header().Set(resultHeader, resultDenied)
		response.Header().Set(receivedHeader, l)
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(denyBody))
		return
	}

	// Return response based on authorization result
	if authResponse.Allowed {
		log.Printf("[HTTP][allowed]: %s", l)
		response.Header().Set(resultHeader, resultAllowed)
		response.Header().Set(receivedHeader, l)

		// Add Cerbos-specific headers for allowed requests
		if authResponse.Action != "" {
			response.Header().Set("X-Cerbos-Action", authResponse.Action)
		}
		if authResponse.PrincipalID != "" {
			response.Header().Set("X-Cerbos-Principal", authResponse.PrincipalID)
		}
		if authResponse.Cache != "" {
			response.Header().Set("X-Cerbos-Cache", authResponse.Cache)
		}

		response.WriteHeader(http.StatusOK)
	} else {
		log.Printf("[HTTP][denied]: %s", l)
		response.Header().Set(resultHeader, resultDenied)
		response.Header().Set(receivedHeader, l)

		// Add detailed status information in headers
		response.Header().Set("X-Cerbos-Status", authResponse.Status)
		if authResponse.Action != "" {
			response.Header().Set("X-Cerbos-Action", authResponse.Action)
		}
		if authResponse.PrincipalID != "" {
			response.Header().Set("X-Cerbos-Principal", authResponse.PrincipalID)
		}
		if authResponse.Cache != "" {
			response.Header().Set("X-Cerbos-Cache", authResponse.Cache)
		}

		// Add service health information for degraded states
		if authResponse.Status == "degraded" || authResponse.Status == "circuit_breaker_open" {
			response.Header().Set("X-Cerbos-Service-Health", "degraded")
			response.Header().Set("X-Cerbos-Circuit-Breaker-State", s.service.GetCircuitBreakerState())
		} else {
			response.Header().Set("X-Cerbos-Service-Health", "healthy")
		}

		// Provide error message based on status
		var errorMessage string
		if authResponse.Reason != "" {
			errorMessage = fmt.Sprintf("denied by ext_authz: %s", authResponse.Reason)
		} else {
			switch authResponse.Status {
			case "invalid_token":
				errorMessage = "denied by ext_authz: invalid or expired JWT token"
			case "degraded":
				errorMessage = "denied by ext_authz: service degraded, authorization failed"
			case "circuit_breaker_open":
				errorMessage = "denied by ext_authz: service temporarily unavailable"
			case "error":
				errorMessage = "denied by ext_authz: authorization service error"
			default:
				errorMessage = fmt.Sprintf("denied by ext_authz: %s", authResponse.Status)
			}
		}

		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(errorMessage))
	}
}

func (s *ExtAuthzServer) startGRPC(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped gRPC server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to start gRPC server: %v", err)
		return
	}
	// Store the port for test only.
	s.grpcPort <- listener.Addr().(*net.TCPAddr).Port

	s.grpcServer = grpc.NewServer()
	authv3.RegisterAuthorizationServer(s.grpcServer, s)

	log.Printf("Starting gRPC server at %s", listener.Addr())
	if err := s.grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC server: %v", err)
		return
	}
}

func (s *ExtAuthzServer) startHTTP(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped HTTP server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to create HTTP server: %v", err)
	}
	// Store the port for test only.
	s.httpPort <- listener.Addr().(*net.TCPAddr).Port
	s.httpServer = &http.Server{Handler: s}

	log.Printf("Starting HTTP server at %s", listener.Addr())
	if err := s.httpServer.Serve(listener); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func (s *ExtAuthzServer) run(httpAddr, grpcAddr string) {
	var wg sync.WaitGroup
	wg.Add(2)
	go s.startHTTP(httpAddr, &wg)
	go s.startGRPC(grpcAddr, &wg)
	wg.Wait()
}

func (s *ExtAuthzServer) stop() {
	if s.grpcServer != nil {
		s.grpcServer.Stop()
		log.Printf("GRPC server stopped")
	}
	if s.httpServer != nil {
		log.Printf("HTTP server stopped: %v", s.httpServer.Close())
	}
	// Shutdown service (which handles telemetry)
	if s.service != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.service.Shutdown(ctx); err != nil {
			log.Printf("Service shutdown error: %v", err)
		}
	}
}

func NewExtAuthzServer() (*ExtAuthzServer, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Create service (this will handle telemetry internally)
	svc, err := service.NewService(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	return &ExtAuthzServer{
		service:  svc,
		httpPort: make(chan int, 1),
		grpcPort: make(chan int, 1),
	}, nil
}

func main() {
	flag.Parse()

	s, err := NewExtAuthzServer()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go s.run(fmt.Sprintf(":%s", *httpPort), fmt.Sprintf(":%s", *grpcPort))
	defer s.stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func returnIfNotTooLong(body string) string {
	// Maximum size of a header accepted by Envoy is 60KiB, so when the request body is bigger than 60KB,
	// we don't return it in a response header to avoid rejecting it by Envoy and returning 431 to the client
	if len(body) > 60000 {
		return "<too-long>"
	}
	return body
}
