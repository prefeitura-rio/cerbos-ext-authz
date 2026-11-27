package main

import (
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
		"/api/v1/x?" + queryToken:                    "/api/v1/x?[REDACTED]=[REDACTED]",
		"/api/v1/x?a%20b=1;flag":                     "/api/v1/x?[REDACTED]=[REDACTED]&flag=[REDACTED]",
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
