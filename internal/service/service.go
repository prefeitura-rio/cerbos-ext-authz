package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/prefeitura-rio/cerbos-ext-authz/internal/cache"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/cerbos"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/circuitbreaker"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/config"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/jwt"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/mapping"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Service handles authorization requests
type Service struct {
	config         *config.Config
	cerbosClient   cerbos.Client
	mappingClient  mapping.Client
	jwtParser      jwt.Parser
	cache          cache.Cache
	circuitBreaker *circuitbreaker.Breaker
	telemetry      *observability.Telemetry
	metrics        *observability.Metrics
}

// AuthorizationRequest represents an authorization request
type AuthorizationRequest struct {
	AuthHeader string `json:"authHeader"`
	Service    string `json:"service"`
	Path       string `json:"path"`
	Method     string `json:"method"`
	Host       string `json:"host"`
}

// AuthorizationResponse represents an authorization response
type AuthorizationResponse struct {
	Allowed     bool   `json:"allowed"`
	Status      string `json:"status"`
	Action      string `json:"action,omitempty"`
	PrincipalID string `json:"principalId,omitempty"`
	Cache       string `json:"cache,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// NewService creates a new authorization service
func NewService(cfg *config.Config) (*Service, error) {
	// Create Cerbos client
	cerbosConfig := &cerbos.Config{
		Endpoint: cfg.CerbosEndpoint,
		Timeout:  cfg.CerbosTimeout,
		MockMode: cfg.MockMode,
	}
	cerbosClient := cerbos.NewClient(cerbosConfig)

	// Create mapping client
	mappingConfig := &mapping.Config{
		// Redis mappings configuration
		RedisSentinelHosts:   cfg.RedisMappingsSentinelHosts,
		RedisSentinelService: cfg.RedisMappingsSentinelService,
		RedisPassword:        cfg.RedisMappingsPassword,
		// Legacy HTTP configuration (kept for fallback)
		BaseURL:  cfg.MappingServiceURL,
		APIToken: cfg.MappingAPIToken,
		Timeout:  cfg.MappingTimeout,
		MockMode: cfg.MockMode,
	}
	mappingClient := mapping.NewClient(mappingConfig)

	// Create JWT parser with JWKS endpoint and issuer validation
	jwtConfig := &jwt.Config{
		JWKSEndpoint:   cfg.JWKSEndpoint,
		ExpectedIssuer: cfg.JWTIssuer,
		Timeout:        cfg.JWTTimeout,
	}
	jwtParser := jwt.NewParser(jwtConfig)

	// Create cache
	cacheConfig := cache.Config{
		Type:          "redis",
		RedisURL:      cfg.RedisURL,
		DefaultTTL:    time.Duration(cfg.CacheTTLSeconds) * time.Second,
		FailedTTL:     time.Duration(cfg.CacheFailedTTLSeconds) * time.Second,
		MaxMemorySize: 10000, // Not used for Redis
	}
	cacheInstance, err := cache.NewCache(cacheConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	// Create circuit breaker
	circuitBreakerConfig := circuitbreaker.Config{
		FailureThreshold:    cfg.CircuitBreakerFailureThreshold,
		RecoveryTime:        cfg.CircuitBreakerRecoveryTime,
		HalfOpenMaxRequests: 3, // Allow 3 requests in half-open state
	}
	circuitBreaker := circuitbreaker.NewBreaker(circuitBreakerConfig)

	// Create telemetry
	telemetryConfig := observability.Config{
		ServiceName:    cfg.OTelServiceName,
		ServiceVersion: "1.0.0",
		Environment:    "production",
		OTelEndpoint:   cfg.OTelEndpoint,
		LogLevel:       cfg.LogLevel,
	}
	telemetry, err := observability.NewTelemetry(telemetryConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create telemetry: %w", err)
	}

	// Create metrics
	var metrics *observability.Metrics
	if telemetry.Meter != nil {
		metrics, err = observability.NewMetrics(telemetry.Meter)
		if err != nil {
			return nil, fmt.Errorf("failed to create metrics: %w", err)
		}
	}

	return &Service{
		config:         cfg,
		cerbosClient:   cerbosClient,
		mappingClient:  mappingClient,
		jwtParser:      jwtParser,
		cache:          cacheInstance,
		circuitBreaker: circuitBreaker,
		telemetry:      telemetry,
		metrics:        metrics,
	}, nil
}

// Authorize performs Cerbos-based authorization and returns an authorization decision
func (s *Service) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error) {
	startTime := time.Now()
	requestID := generateRequestID()

	// Debug logging: Log complete request details
	if s.telemetry != nil && s.telemetry.Logger != nil {
		s.telemetry.Logger.WithFields(map[string]interface{}{
			"request_id":  requestID,
			"method":      req.Method,
			"path":        req.Path,
			"host":        req.Host,
			"service":     req.Service,
			"auth_header": req.AuthHeader,
		}).Info("Complete request details for debugging")
	}

	// Safe tracing with panic protection
	var span trace.Span
	if s.telemetry != nil && s.telemetry.Tracer != nil && s.telemetry.Provider != nil && s.telemetry.Meter != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Log the panic but don't crash the service
					if s.telemetry != nil && s.telemetry.Logger != nil {
						s.telemetry.Logger.WithField("panic", r).Error("Tracing panic recovered, continuing without tracing")
					}
				}
			}()
			ctx, span = s.telemetry.Tracer.Start(ctx, "authorize",
				trace.WithAttributes(
					attribute.String("request_id", requestID),
					attribute.String("service", req.Service),
					attribute.String("path", req.Path),
					attribute.String("method", req.Method),
				),
			)
		}()
		if span != nil {
			defer func() {
				defer func() {
					if r := recover(); r != nil {
						// Log the panic but don't crash the service
						if s.telemetry != nil && s.telemetry.Logger != nil {
							s.telemetry.Logger.WithField("panic", r).Error("Span.End() panic recovered")
						}
					}
				}()
				span.End()
			}()
		}
	}

	// Record metrics
	if s.metrics != nil {
		s.metrics.RequestsTotal.Add(ctx, 1)
		defer func() {
			s.metrics.ResponseTime.Record(ctx, time.Since(startTime).Seconds())
		}()
	}

	// Extract principal from JWT token
	principalID, roles, err := s.extractPrincipal(req.AuthHeader)
	if err != nil {
		return &AuthorizationResponse{
			Allowed: false,
			Status:  "invalid_token",
			Reason:  err.Error(),
			Cache:   "miss",
		}, nil
	}

	// Determine service if not explicitly provided
	service := req.Service
	if service == "" {
		service = s.determineService(req.Host)
	}

	// Generate cache key based on principal, service, path, method
	cacheKey := s.generateCacheKey(principalID, service, req.Path, req.Method)

	// Check cache first
	cachedResult, err := s.cache.Get(ctx, cacheKey)
	if err == nil && cachedResult != nil {
		// Cache hit
		if s.metrics != nil {
			s.metrics.CacheHits.Add(ctx, 1)
		}

		if s.telemetry != nil {
			s.telemetry.LogCache("get", cacheKey, true, time.Since(startTime))
		}

		response := s.convertCacheToResponse(cachedResult, "hit")
		s.logRequest(requestID, principalID, response.Status, true, time.Since(startTime), nil)
		return response, nil
	}

	// Cache miss
	if s.metrics != nil {
		s.metrics.CacheMisses.Add(ctx, 1)
	}

	if s.telemetry != nil {
		s.telemetry.LogCache("get", cacheKey, false, time.Since(startTime))
	}

	// Get action from mapping service
	log.Printf("[MAPPING] Resolving action for: %s %s", req.Method, req.Path)
	action, _, err := s.mappingClient.GetAction(ctx, req.Path, req.Method)
	if err != nil {
		log.Printf("[MAPPING] ✗ Resolution failed: %v", err)
	} else {
		log.Printf("[MAPPING] ✓ Resolved to action: %s", action)
	}

	// Check for public action - always allow without Cerbos check
	if action == "public" {
		log.Printf("[AUTH] Public endpoint - allowing without authorization")
		return &AuthorizationResponse{
			Allowed:     true,
			Status:      "allowed",
			Action:      action,
			PrincipalID: principalID,
			Cache:       "miss", // Public actions are not cached
			Reason:      "public endpoint",
		}, nil
	}

	// Check for authenticated action - only validate JWT, no role checks
	if action == "authenticated" {
		// If we got here, JWT was already validated in extractPrincipal
		// Check if user is authenticated (not anonymous)
		if principalID == "anonymous" {
			log.Printf("[AUTH] Authenticated endpoint requires valid JWT - denying anonymous user")
			return &AuthorizationResponse{
				Allowed:     false,
				Status:      "denied",
				Action:      action,
				PrincipalID: principalID,
				Cache:       "miss", // Authentication failures are not cached
				Reason:      "authentication required",
			}, nil
		}

		log.Printf("[AUTH] Authenticated endpoint - JWT valid for principal: %s", principalID)
		return &AuthorizationResponse{
			Allowed:     true,
			Status:      "allowed",
			Action:      action,
			PrincipalID: principalID,
			Cache:       "miss", // Authenticated actions are not cached to ensure fresh JWT validation
			Reason:      "valid JWT token",
		}, nil
	}

	if err != nil {
		if s.telemetry != nil {
			s.telemetry.Logger.WithError(err).Warn("No action mapping found - denying request for security")
		}
		// Security: Deny request when no mapping exists
		response := &AuthorizationResponse{
			Allowed:     false,
			Status:      "no_action_mapping",
			Action:      "",
			PrincipalID: principalID,
			Cache:       "miss",
			Reason:      "no action mapping found for endpoint",
		}
		s.logRequest(requestID, principalID, response.Status, false, time.Since(startTime), err)
		return response, nil
	}

	// Check circuit breaker
	if s.config.CircuitBreakerEnabled && s.circuitBreaker.IsOpen() {
		// Circuit breaker is open, handle based on failure mode
		response := s.handleCircuitBreakerOpen(action, principalID)
		s.logRequest(requestID, principalID, response.Status, false, time.Since(startTime), nil)
		return response, nil
	}

	// Perform Cerbos authorization
	var authResult *cerbos.CheckResourcesResponse
	var authErr error

	if s.config.CircuitBreakerEnabled {
		// Use circuit breaker
		authErr = s.circuitBreaker.Execute(ctx, func() error {
			result, err := s.authorizeToCerbos(ctx, principalID, roles, req.Path, req.Method, action)
			if err != nil {
				return err
			}
			authResult = result
			return nil
		})
	} else {
		// Direct authorization
		authResult, authErr = s.authorizeToCerbos(ctx, principalID, roles, req.Path, req.Method, action)
	}

	// Handle authorization result
	if authErr != nil {
		// Authorization failed
		if s.metrics != nil {
			s.metrics.ErrorsTotal.Add(ctx, 1)
		}

		response := s.handleAuthorizationError(authErr, action, principalID)
		s.logRequest(requestID, principalID, response.Status, false, time.Since(startTime), authErr)
		return response, nil
	}

	// Create response from Cerbos result
	response := s.createResponseFromCerbos(authResult, action, principalID, "miss")

	// Cache the result
	s.cacheAuthResult(ctx, cacheKey, response)

	s.logRequest(requestID, principalID, response.Status, false, time.Since(startTime), nil)

	return response, nil
}

// authorizeToCerbos calls Cerbos to perform authorization
func (s *Service) authorizeToCerbos(ctx context.Context, principalID string, roles []string, path, method, action string) (*cerbos.CheckResourcesResponse, error) {
	// Safe tracing with panic protection
	var span trace.Span
	if s.telemetry != nil && s.telemetry.Tracer != nil && s.telemetry.Provider != nil && s.telemetry.Meter != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Log the panic but don't crash the service
					if s.telemetry != nil && s.telemetry.Logger != nil {
						s.telemetry.Logger.WithField("panic", r).Error("Tracing panic recovered, continuing without tracing")
					}
				}
			}()
			ctx, span = s.telemetry.Tracer.Start(ctx, "authorize_with_cerbos")
		}()
		if span != nil {
			defer func() {
				defer func() {
					if r := recover(); r != nil {
						// Log the panic but don't crash the service
						if s.telemetry != nil && s.telemetry.Logger != nil {
							s.telemetry.Logger.WithField("panic", r).Error("Span.End() panic recovered")
						}
					}
				}()
				span.End()
			}()
		}
	}

	startTime := time.Now()

	// Build Cerbos request
	request := &cerbos.CheckResourcesRequest{
		RequestID: generateRequestID(),
		Principal: cerbos.Principal{
			ID:            principalID,
			Roles:         roles,
			PolicyVersion: "default",
			Attr: map[string]interface{}{
				"isAuthenticated": principalID != "anonymous",
				"userId":          principalID,
			},
		},
		Resources: []cerbos.Resource{
			{
				Resource: cerbos.ResourceInfo{
					Kind: "generic",  // Use generic resource kind as in Python reference
					ID:   "resource", // Simple resource ID as in Python reference
					Attr: map[string]interface{}{
						"path":   path,
						"method": method,
					},
				},
				Actions: []string{action},
			},
		},
	}

	// Log Cerbos authorization request with CPF
	log.Printf("[CERBOS] Checking authorization: principal=%s, action=%s, resource=%s %s, roles=%v",
		principalID, action, method, path, roles)

	result, err := s.cerbosClient.CheckResources(ctx, request)
	duration := time.Since(startTime)

	// Log Cerbos authorization result
	if err != nil {
		log.Printf("[CERBOS] ✗ Authorization check failed for principal=%s: %v", principalID, err)
	} else if result != nil {
		allowed := result.IsAllowed(action)
		if allowed {
			log.Printf("[CERBOS] ✓ Authorization ALLOWED: principal=%s, action=%s, resource=%s %s",
				principalID, action, method, path)
		} else {
			log.Printf("[CERBOS] ✗ Authorization DENIED: principal=%s, action=%s, resource=%s %s",
				principalID, action, method, path)
		}
	}

	// Record metrics
	if s.metrics != nil {
		if err == nil && result != nil && result.IsAllowed(action) {
			s.metrics.ValidationSuccess.Add(ctx, 1)
		} else {
			s.metrics.ValidationFailure.Add(ctx, 1)
		}
	}

	// Log authorization
	if s.telemetry != nil {
		allowed := result != nil && result.IsAllowed(action)
		s.telemetry.LogValidation(
			"", // requestID will be set by caller
			principalID,
			allowed,
			0.0,        // No score in Cerbos
			[]string{}, // No error codes in this context
			duration,
		)
	}

	return result, err
}

// cacheAuthResult caches the authorization result
func (s *Service) cacheAuthResult(ctx context.Context, key string, response *AuthorizationResponse) {
	// Convert to cache format
	cacheResult := &cache.ValidationResult{
		Success:     response.Allowed,
		Score:       0.0, // No score in Cerbos
		Action:      response.Action,
		ChallengeTS: "", // Not applicable
		Hostname:    "", // Not applicable
		ErrorCodes:  []string{response.Status},
		Timestamp:   time.Now(),
	}

	// Determine TTL based on result
	ttl := time.Duration(s.config.CacheTTLSeconds) * time.Second
	if !response.Allowed {
		ttl = time.Duration(s.config.CacheFailedTTLSeconds) * time.Second
	}

	// Cache the result
	if err := s.cache.Set(ctx, key, cacheResult, ttl); err != nil {
		if s.telemetry != nil {
			s.telemetry.Logger.WithError(err).Warn("Failed to cache authorization result")
		}
	}
}

// createResponseFromCerbos creates an authorization response from Cerbos result
func (s *Service) createResponseFromCerbos(result *cerbos.CheckResourcesResponse, action, principalID, cacheStatus string) *AuthorizationResponse {
	allowed := result.IsAllowed(action)
	status := "allowed"
	reason := ""

	if !allowed {
		status = "denied"
		if decision := result.GetDecision(action); decision != "" {
			reason = "policy_denied" // Generic reason since Cerbos API returns simple strings
		}
	}

	return &AuthorizationResponse{
		Allowed:     allowed,
		Status:      status,
		Action:      action,
		PrincipalID: principalID,
		Cache:       cacheStatus,
		Reason:      reason,
	}
}

// handleCircuitBreakerOpen handles requests when circuit breaker is open
func (s *Service) handleCircuitBreakerOpen(action, principalID string) *AuthorizationResponse {
	if s.config.FailureMode == "fail_open" {
		return &AuthorizationResponse{
			Allowed:     true,
			Status:      "degraded",
			Action:      action,
			PrincipalID: principalID,
			Cache:       "miss",
			Reason:      "circuit breaker open, fail-open mode",
		}
	}

	return &AuthorizationResponse{
		Allowed:     false,
		Status:      "circuit_breaker_open",
		Action:      action,
		PrincipalID: principalID,
		Cache:       "miss",
		Reason:      "circuit breaker open, fail-closed mode",
	}
}

// handleAuthorizationError handles authorization errors
func (s *Service) handleAuthorizationError(err error, action, principalID string) *AuthorizationResponse {
	if s.config.FailureMode == "fail_open" {
		return &AuthorizationResponse{
			Allowed:     true,
			Status:      "degraded",
			Action:      action,
			PrincipalID: principalID,
			Cache:       "miss",
			Reason:      fmt.Sprintf("authorization error: %v", err),
		}
	}

	return &AuthorizationResponse{
		Allowed:     false,
		Status:      "error",
		Action:      action,
		PrincipalID: principalID,
		Cache:       "miss",
		Reason:      fmt.Sprintf("authorization error: %v", err),
	}
}

// logRequest logs the request with telemetry
func (s *Service) logRequest(requestID, principalID, status string, cacheHit bool, responseTime time.Duration, err error) {
	if s.telemetry != nil {
		s.telemetry.LogRequest(observability.LogFields{
			RequestID:           requestID,
			Token:               principalID, // Using principalID instead of token
			ValidationResult:    status,
			CacheHit:            cacheHit,
			ResponseTime:        responseTime,
			Error:               err,
			CircuitBreakerState: s.circuitBreaker.GetStateString(),
		})
	}
}

// GetHealth returns the health status of the service
func (s *Service) GetHealth() map[string]interface{} {
	stats := s.circuitBreaker.GetStats()
	cacheStats := s.cache.GetStats()

	return map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"circuit_breaker": map[string]interface{}{
			"state":          stats.State,
			"failure_count":  stats.FailureCount,
			"total_requests": stats.TotalRequests,
			"total_failures": stats.TotalFailures,
		},
		"cache": map[string]interface{}{
			"hits":   cacheStats.Hits,
			"misses": cacheStats.Misses,
			"size":   cacheStats.Size,
		},
		"config": map[string]interface{}{
			"cerbos_endpoint":     s.config.CerbosEndpoint,
			"mapping_service_url": s.config.MappingServiceURL,
			"jwks_endpoint":       s.config.JWKSEndpoint,
			"failure_mode":        s.config.FailureMode,
			"mock_mode":           s.config.MockMode,
		},
	}
}

// GetMetrics returns the current metrics
func (s *Service) GetMetrics() map[string]interface{} {
	stats := s.circuitBreaker.GetStats()
	cacheStats := s.cache.GetStats()

	return map[string]interface{}{
		"circuit_breaker": stats,
		"cache":           cacheStats,
	}
}

// GetCircuitBreakerState returns the current circuit breaker state as a string
func (s *Service) GetCircuitBreakerState() string {
	if s.circuitBreaker != nil {
		return s.circuitBreaker.GetStateString()
	}
	return "unknown"
}

// Shutdown gracefully shuts down the service
func (s *Service) Shutdown(ctx context.Context) error {
	if s.telemetry != nil {
		return s.telemetry.Shutdown(ctx)
	}
	return nil
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// extractPrincipal extracts principal ID and roles from the authorization header
func (s *Service) extractPrincipal(authHeader string) (string, []string, error) {
	if authHeader == "" {
		// No auth header - anonymous user
		return "anonymous", []string{}, nil
	}

	// Extract Bearer token
	token, err := jwt.ExtractBearerToken(authHeader)
	if err != nil {
		// Invalid auth header format - treat as anonymous
		return "anonymous", []string{}, nil
	}

	// Parse and validate JWT token (includes signature verification, expiration, nbf checks)
	claims, err := s.jwtParser.ParseToken(token)
	if err != nil {
		return "", nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	principalID := claims.GetUserID()
	if principalID == "" {
		principalID = "anonymous"
	}

	roles := claims.GetRoles()

	return principalID, roles, nil
}

// determineService determines the service name from the host header
func (s *Service) determineService(host string) string {
	// Simple heuristics based on host prefix
	switch {
	case strings.HasPrefix(host, "go-api"):
		return "go"
	case strings.HasPrefix(host, "rmi-api"):
		return "rmi"
	case strings.HasPrefix(host, "admin-api"):
		return "admin"
	default:
		return "go" // Default service
	}
}

// generateCacheKey generates a cache key for authorization results
func (s *Service) generateCacheKey(principalID, service, path, method string) string {
	return cache.GenerateCacheKey(fmt.Sprintf("%s:%s:%s:%s", principalID, service, path, method))
}

// convertCacheToResponse converts cached result to authorization response
func (s *Service) convertCacheToResponse(cachedResult *cache.ValidationResult, cacheStatus string) *AuthorizationResponse {
	status := "denied"
	if cachedResult.Success {
		status = "allowed"
	}

	reason := ""
	if len(cachedResult.ErrorCodes) > 0 {
		reason = strings.Join(cachedResult.ErrorCodes, ", ")
	}

	return &AuthorizationResponse{
		Allowed: cachedResult.Success,
		Status:  status,
		Action:  cachedResult.Action,
		Cache:   cacheStatus,
		Reason:  reason,
	}
}
