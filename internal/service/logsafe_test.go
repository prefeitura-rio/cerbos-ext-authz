package service

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric/noop"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/prefeitura-rio/cerbos-ext-authz/internal/cache"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/cerbos"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/jwt"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/mapping"
	"github.com/prefeitura-rio/cerbos-ext-authz/internal/observability"
)

const syntheticCPF = "12345678909"

func TestPrincipalForLogHidesThePrincipal(t *testing.T) {
	got := PrincipalForLog(syntheticCPF)
	if strings.Contains(got, syntheticCPF) || !strings.HasPrefix(got, "user:") || len(got) != len("user:")+16 {
		t.Fatalf("PrincipalForLog(%q) = %q, want a user:<16 hex> pseudonym", syntheticCPF, got)
	}
	if PrincipalForLog(syntheticCPF) != got {
		t.Fatal("the pseudonym must be stable within the process to correlate log lines")
	}
	if PrincipalForLog("98765432100") == got {
		t.Fatal("different principals must get different pseudonyms")
	}
	for _, keep := range []string{"", "anonymous", "unknown"} {
		if PrincipalForLog(keep) != keep {
			t.Errorf("PrincipalForLog(%q) = %q, want it unchanged", keep, PrincipalForLog(keep))
		}
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

type fixedAction string

func (a fixedAction) GetAction(context.Context, string, string) (string, *mapping.Mapping, error) {
	return string(a), nil, nil
}

type citizenToken struct{}

func (citizenToken) ParseToken(string) (*jwt.Claims, error) {
	return &jwt.Claims{PreferredUsername: syntheticCPF, Sub: "f3b1c7a0-sub"}, nil
}

func TestAuthenticatedEndpointLogsOnlyThePseudonym(t *testing.T) {
	buf := captureLog(t)
	s := &Service{
		mappingClient: fixedAction("authenticated"),
		jwtParser:     citizenToken{},
		cache:         cache.NewMemoryCache(cache.Config{}),
	}
	resp, err := s.Authorize(context.Background(), &AuthorizationRequest{AuthHeader: "Bearer x.y.z", Method: "GET", Path: "/api/v1/me", Host: "services.example.test"})
	if err != nil || !resp.Allowed {
		t.Fatalf("Authorize = %+v, %v; want allowed", resp, err)
	}
	if resp.PrincipalID != syntheticCPF {
		t.Fatalf("the decision must keep the real principal, got %q", resp.PrincipalID)
	}
	logs := buf.String()
	if strings.Contains(logs, syntheticCPF) || !strings.Contains(logs, "principal: "+PrincipalForLog(syntheticCPF)) {
		t.Fatalf("[AUTH] log must carry only the pseudonym:\n%s", logs)
	}
}

func TestAuthorizeToCerbosLogsOnlyThePseudonym(t *testing.T) {
	buf := captureLog(t)
	s := &Service{cerbosClient: cerbos.NewClient(&cerbos.Config{MockMode: true})}
	for _, action := range []string{"health:check", "api:write"} {
		if _, err := s.authorizeToCerbos(context.Background(), syntheticCPF, []string{"authenticated"}, "/api/v1/citizen", "POST", action); err != nil {
			t.Fatalf("authorizeToCerbos(%s): %v", action, err)
		}
	}
	logs := buf.String()
	if strings.Contains(logs, syntheticCPF) {
		t.Fatalf("Cerbos logs leak the principal:\n%s", logs)
	}
	if !strings.Contains(logs, "principal="+PrincipalForLog(syntheticCPF)) {
		t.Fatalf("Cerbos logs lost the principal pseudonym:\n%s", logs)
	}
}

// citizenPath is a route of app-rmi that carries the citizen's CPF.
const citizenPath = "/v1/citizen/" + syntheticCPF + "/wallet"

func TestAuthorizeMasksTheCPFInThePathOfLogsAndSpans(t *testing.T) {
	buf := captureLog(t)
	var structured bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&structured)
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	s := &Service{
		mappingClient: fixedAction("authenticated"),
		jwtParser:     citizenToken{},
		cache:         cache.NewMemoryCache(cache.Config{}),
		telemetry: &observability.Telemetry{
			Tracer:   provider.Tracer("test"),
			Meter:    noop.NewMeterProvider().Meter("test"),
			Logger:   logger,
			Provider: provider,
		},
	}
	resp, err := s.Authorize(context.Background(), &AuthorizationRequest{AuthHeader: "Bearer x.y.z", Method: "GET", Path: citizenPath, Host: "services.example.test"})
	if err != nil || !resp.Allowed {
		t.Fatalf("Authorize = %+v, %v; want allowed", resp, err)
	}

	logs := buf.String() + structured.String()
	if strings.Contains(logs, syntheticCPF) {
		t.Fatalf("logs leak the CPF in the path:\n%s", logs)
	}
	if !strings.Contains(buf.String(), "Resolving action for: GET /v1/citizen/[CPF]/wallet") ||
		!strings.Contains(structured.String(), `path="/v1/citizen/[CPF]/wallet"`) {
		t.Fatalf("logs lost the masked path:\n%s", logs)
	}
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	for _, attr := range spans[0].Attributes() {
		if attr.Key == "path" && attr.Value.AsString() != "/v1/citizen/[CPF]/wallet" {
			t.Fatalf("span path = %q, want the masked path", attr.Value.AsString())
		}
		if strings.Contains(attr.Value.Emit(), syntheticCPF) {
			t.Fatalf("span attribute %s leaks the CPF: %q", attr.Key, attr.Value.Emit())
		}
	}
}

func TestRequestLogFieldsMaskTheCPFInThePath(t *testing.T) {
	fields := requestLogFields("req_1", &AuthorizationRequest{Method: "GET", Path: citizenPath})
	if fields["path"] != "/v1/citizen/[CPF]/wallet" {
		t.Fatalf("path = %v, want the CPF masked", fields["path"])
	}
}

func TestAuthorizeToCerbosMasksTheCPFInTheResourcePath(t *testing.T) {
	buf := captureLog(t)
	s := &Service{cerbosClient: cerbos.NewClient(&cerbos.Config{MockMode: true})}
	for _, action := range []string{"health:check", "api:write"} {
		if _, err := s.authorizeToCerbos(context.Background(), "anonymous", []string{"authenticated"}, citizenPath, "PUT", action); err != nil {
			t.Fatalf("authorizeToCerbos(%s): %v", action, err)
		}
	}
	logs := buf.String()
	if strings.Contains(logs, syntheticCPF) {
		t.Fatalf("Cerbos logs leak the CPF in the path:\n%s", logs)
	}
	if !strings.Contains(logs, "resource=PUT /v1/citizen/[CPF]/wallet") {
		t.Fatalf("Cerbos logs lost the masked resource path:\n%s", logs)
	}
}
