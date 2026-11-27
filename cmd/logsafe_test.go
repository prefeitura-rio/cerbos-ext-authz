package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/prefeitura-rio/cerbos-ext-authz/internal/service"
)

const queryToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"

func TestRedactQuery(t *testing.T) {
	cases := map[string]string{
		"/api/v1/x":                                  "/api/v1/x",
		"/api/v1/x?":                                 "/api/v1/x",
		"/api/v1/x#frag":                             "/api/v1/x",
		"/api/v1/x?access_token=" + queryToken:       "/api/v1/x?access_token=[REDACTED]",
		"/api/v1/x?cpf=12345678909&page=2#top":       "/api/v1/x?cpf=[REDACTED]&page=[REDACTED]",
		"/api/v1/x?" + queryToken:                    "/api/v1/x?[REDACTED]",
		"/api/v1/x?12345678909":                      "/api/v1/x?[REDACTED]",
		"/api/v1/x?abc123&page=1":                    "/api/v1/x?[REDACTED]&page=[REDACTED]",
		"/api/v1/x?a%20b=1;flag":                     "/api/v1/x?[REDACTED]=[REDACTED]&[REDACTED]",
		"/api/v1/x?" + queryToken + "x=1":            "/api/v1/x?[REDACTED]=[REDACTED]",
		"https://app.example.test/p?code=abc&state=": "https://app.example.test/p?code=[REDACTED]&state=[REDACTED]",
	}
	for in, want := range cases {
		if got := redactQuery(in); got != want {
			t.Errorf("redactQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func requestWithQuery() *authv3.CheckRequest {
	req := testRequest()
	httpAttrs := req.Attributes.Request.Http
	httpAttrs.Path = "/secret/internal/path?access_token=" + queryToken + "&cpf=12345678909"
	httpAttrs.Headers[":path"] = httpAttrs.Path
	httpAttrs.Headers["x-envoy-original-path"] = httpAttrs.Path
	httpAttrs.Headers["referer"] = "https://app.example.test/login?code=" + queryToken
	return req
}

func assertNoQueryValues(t *testing.T, where, got string) {
	t.Helper()
	for _, secret := range []string{queryToken, "12345678909"} {
		if strings.Contains(got, secret) {
			t.Errorf("%s leaks a query string value %q: %s", where, secret, got)
		}
	}
}

func TestGRPCLogsAndReceivedHeaderRedactQueryString(t *testing.T) {
	buf := captureLog(t)
	s := &ExtAuthzServer{}
	req := requestWithQuery()
	original := req.Attributes.Request.Http.Path
	allowed := s.allow(req)
	withDetails := s.allowWithDetails(req, &service.AuthorizationResponse{Allowed: true})
	s.deny(req)
	s.denyWithDetails(req, &service.AuthorizationResponse{Status: "denied"})

	logs := buf.String()
	assertNoQueryValues(t, "log", logs)
	if !strings.Contains(logs, "/secret/internal/path?access_token=[REDACTED]&cpf=[REDACTED]") {
		t.Errorf("log lost the path and the query parameter names:\n%s", logs)
	}
	assertNoQueryValues(t, receivedHeader, headerKeys(allowed.GetOkResponse().GetHeaders())[receivedHeader])
	assertNoQueryValues(t, receivedHeader, headerKeys(withDetails.GetOkResponse().GetHeaders())[receivedHeader])
	if req.Attributes.Request.Http.Path != original || req.Attributes.Request.Http.Headers["x-envoy-original-path"] != original {
		t.Errorf("redaction changed the request itself: %q", req.Attributes.Request.Http.Path)
	}
}

func TestLoggableAttributesKeepsOtherHeaders(t *testing.T) {
	attrs := loggableAttributes(requestWithQuery().GetAttributes())
	if got := attrs.GetRequest().GetHttp().GetHeaders()["host"]; got != "services.example.test" {
		t.Errorf("headers without a URL must be kept, host = %q", got)
	}
	if got := attrs.GetRequest().GetHttp().GetHeaders()["referer"]; got != "https://app.example.test/login?code=[REDACTED]" {
		t.Errorf("referer = %q, want the query redacted", got)
	}
}

func TestHTTPLogsAndReceivedHeaderRedactQueryString(t *testing.T) {
	buf := captureLog(t)
	s := &ExtAuthzServer{}
	target := "http://services.example.test/secret/internal/path?access_token=" + queryToken + "&cpf=12345678909"
	req := httptest.NewRequest(http.MethodOptions, target, nil)
	req.Header.Set("X-Envoy-Original-Path", "/secret/internal/path?access_token="+queryToken)
	req.Header.Set("Referer", "https://app.example.test/login?code="+queryToken)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	received := rec.Header().Get(receivedHeader)
	assertNoQueryValues(t, "log", buf.String())
	assertNoQueryValues(t, receivedHeader, received)
	if !strings.Contains(received, "/secret/internal/path?access_token=[REDACTED]&cpf=[REDACTED]") {
		t.Errorf("%s lost the path and the query parameter names: %q", receivedHeader, received)
	}
	if req.Header.Get("X-Envoy-Original-Path") != "/secret/internal/path?access_token="+queryToken {
		t.Errorf("redaction changed the request headers: %q", req.Header.Get("X-Envoy-Original-Path"))
	}
}

// syntheticCPF is a synthetic CPF (valid check digits, no real person) in an
// app-rmi route that carries the citizen's CPF in the path.
const syntheticCPF = "12345678909"

func assertNoCPF(t *testing.T, where, got string) {
	t.Helper()
	if strings.Contains(got, syntheticCPF) {
		t.Errorf("%s leaks the CPF in the path: %s", where, got)
	}
}

func requestWithCPFPath() *authv3.CheckRequest {
	req := testRequest()
	httpAttrs := req.Attributes.Request.Http
	httpAttrs.Path = "/rmi/v1/citizen/" + syntheticCPF + "/wallet?page=1"
	httpAttrs.Headers[":path"] = httpAttrs.Path
	httpAttrs.Headers["x-envoy-original-path"] = httpAttrs.Path
	httpAttrs.Headers["referer"] = "https://app.example.test/citizen/" + syntheticCPF
	return req
}

func TestGRPCLogsAndReceivedHeaderMaskTheCPFInThePath(t *testing.T) {
	buf := captureLog(t)
	s := &ExtAuthzServer{}
	req := requestWithCPFPath()
	original := req.Attributes.Request.Http.Path
	allowed := s.allow(req)
	withDetails := s.allowWithDetails(req, &service.AuthorizationResponse{Allowed: true})
	s.deny(req)
	s.denyWithDetails(req, &service.AuthorizationResponse{Status: "denied"})

	logs := buf.String()
	assertNoCPF(t, "log", logs)
	if !strings.Contains(logs, "/rmi/v1/citizen/[CPF]/wallet?page=[REDACTED]") {
		t.Errorf("log lost the masked path:\n%s", logs)
	}
	assertNoCPF(t, receivedHeader, headerKeys(allowed.GetOkResponse().GetHeaders())[receivedHeader])
	assertNoCPF(t, receivedHeader, headerKeys(withDetails.GetOkResponse().GetHeaders())[receivedHeader])
	if req.Attributes.Request.Http.Path != original || req.Attributes.Request.Http.Headers["x-envoy-original-path"] != original {
		t.Errorf("masking changed the request itself: %q", req.Attributes.Request.Http.Path)
	}
}

// The gRPC Check logs the path before it asks the service for the decision.
// The zero Service has no mapping client and panics right after these lines,
// which is enough to read them.
func TestGRPCCheckLogsMaskTheCPFInThePath(t *testing.T) {
	for host, want := range map[string]string{
		"services.example.test":     "[DEBUG] gRPC Request - Method: GET, Path: /rmi/v1/citizen/[CPF]/wallet, Host: services.example.test",
		"rmi.rmi.svc.cluster.local": "using direct path: /rmi/v1/citizen/[CPF]/wallet",
	} {
		buf := captureLog(t)
		s := &ExtAuthzServer{service: &service.Service{}}
		req := requestWithCPFPath()
		req.Attributes.Request.Http.Headers["host"] = host
		func() {
			defer func() { _ = recover() }()
			_, _ = s.Check(context.Background(), req)
		}()
		logs := buf.String()
		assertNoCPF(t, "log", logs)
		if !strings.Contains(logs, want) || !strings.Contains(logs, "Path: /rmi/v1/citizen/[CPF]/wallet") {
			t.Errorf("host %s: log lost the masked path:\n%s", host, logs)
		}
	}
}

func TestHTTPLogsAndReceivedHeaderMaskTheCPFInThePath(t *testing.T) {
	buf := captureLog(t)
	s := &ExtAuthzServer{}
	target := "http://services.example.test/rmi/v1/citizen/" + syntheticCPF + "/wallet"
	req := httptest.NewRequest(http.MethodOptions, target, nil)
	req.Header.Set("X-Envoy-Original-Path", "/rmi/v1/citizen/"+syntheticCPF+"/wallet")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	received := rec.Header().Get(receivedHeader)
	logs := buf.String()
	assertNoCPF(t, "log", logs)
	assertNoCPF(t, receivedHeader, received)
	if !strings.Contains(logs, "[DEBUG] HTTP Request - Method: OPTIONS, Path: /rmi/v1/citizen/[CPF]/wallet") ||
		!strings.Contains(received, "/rmi/v1/citizen/[CPF]/wallet") {
		t.Errorf("log or %s lost the masked path:\n%s\n%s", receivedHeader, logs, received)
	}
	if req.Header.Get("X-Envoy-Original-Path") != "/rmi/v1/citizen/"+syntheticCPF+"/wallet" {
		t.Errorf("masking changed the request headers: %q", req.Header.Get("X-Envoy-Original-Path"))
	}
}
