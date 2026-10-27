package main

import (
	"bytes"
	"log"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/prefeitura-rio/cerbos-ext-authz/internal/service"
)

func testRequest() *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host:   "services.example.test",
					Method: "GET",
					Path:   "/secret/internal/path",
					Headers: map[string]string{
						"host": "services.example.test",
					},
				},
			},
		},
	}
}

func headerKeys(hs []*corev3.HeaderValueOption) map[string]string {
	out := map[string]string{}
	for _, h := range hs {
		out[strings.ToLower(h.GetHeader().GetKey())] = h.GetHeader().GetValue()
	}
	return out
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

func assertNoDebugHeaders(t *testing.T, resp *authv3.CheckResponse) {
	t.Helper()
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("expected a denied response, got %T", resp.GetHttpResponse())
	}
	for k := range headerKeys(denied.GetHeaders()) {
		if strings.HasPrefix(k, "x-cerbos-") || strings.HasPrefix(k, "x-ext-authz-check-") {
			t.Errorf("denied response leaks debug header %q", k)
		}
	}
	if len(denied.GetHeaders()) != 0 {
		t.Errorf("expected no headers on denied response, got %d", len(denied.GetHeaders()))
	}
}

func TestDenyWithDetailsDoesNotLeakHeadersButLogsThem(t *testing.T) {
	for _, status := range []string{"invalid_token", "degraded", "circuit_breaker_open", "error"} {
		t.Run(status, func(t *testing.T) {
			buf := captureLog(t)
			s := &ExtAuthzServer{}
			resp := s.denyWithDetails(testRequest(), &service.AuthorizationResponse{
				Status:      status,
				Action:      "read",
				PrincipalID: "12345678901",
				Cache:       "hit",
			})
			assertNoDebugHeaders(t, resp)
			if resp.GetDeniedResponse().GetStatus().GetCode() != 403 {
				t.Errorf("status changed: %v", resp.GetDeniedResponse().GetStatus())
			}
			if !strings.HasPrefix(resp.GetDeniedResponse().GetBody(), "denied by ext_authz: ") {
				t.Errorf("unexpected body %q", resp.GetDeniedResponse().GetBody())
			}
			logs := buf.String()
			for _, want := range []string{
				"x-ext-authz-check-result=denied",
				"x-cerbos-status=\"" + status + "\"",
				"x-cerbos-action=\"read\"",
				"x-cerbos-principal=\"12345678901\"",
				"x-cerbos-cache=\"hit\"",
				"x-cerbos-service-health=",
				"x-cerbos-circuit-breaker-state=",
				"/secret/internal/path", // request attributes (received) still logged
			} {
				if !strings.Contains(logs, want) {
					t.Errorf("log missing %q; got:\n%s", want, logs)
				}
			}
		})
	}
}

func TestDenyDoesNotLeakHeaders(t *testing.T) {
	buf := captureLog(t)
	s := &ExtAuthzServer{}
	resp := s.deny(testRequest())
	assertNoDebugHeaders(t, resp)
	if resp.GetDeniedResponse().GetBody() != denyBody {
		t.Errorf("body changed: %q", resp.GetDeniedResponse().GetBody())
	}
	if !strings.Contains(buf.String(), "[denied]") || !strings.Contains(buf.String(), "/secret/internal/path") {
		t.Errorf("deny log missing info: %s", buf.String())
	}
}

func TestAllowWithDetailsKeepsUpstreamHeaders(t *testing.T) {
	captureLog(t)
	s := &ExtAuthzServer{}
	resp := s.allowWithDetails(testRequest(), &service.AuthorizationResponse{
		Allowed:     true,
		Action:      "read",
		PrincipalID: "12345678901",
		Cache:       "miss",
	})
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatalf("expected ok response")
	}
	got := headerKeys(ok.GetHeaders())
	want := map[string]string{
		resultHeader:         resultAllowed,
		"x-cerbos-action":    "read",
		"x-cerbos-principal": "12345678901",
		"x-cerbos-cache":     "miss",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("allowed header %s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got[receivedHeader]; !ok {
		t.Errorf("allowed response lost %s", receivedHeader)
	}
}
