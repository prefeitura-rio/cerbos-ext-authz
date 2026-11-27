package jwt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Synthetic citizen identifiers: never real data.
const (
	testSub      = "f1c2a3b4-0000-4000-8000-sintetico0001"
	testUsername = "12345678901"
	testIssuer   = "https://keycloak.example.test/realms/teste"
	testKid      = "kid-teste"
)

func jwksServer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(JWKS{Keys: []JWK{{
		Kid: testKid,
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestParseTokenDebugLogNeverCarriesTheSubject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	srv := jwksServer(t, &key.PublicKey)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":                testSub,
		"preferred_username": testUsername,
		"iss":                testIssuer,
		"exp":                time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = testKid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	t.Setenv("JWT_DEBUG", "true")
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	p := NewParser(&Config{JWKSEndpoint: srv.URL, ExpectedIssuer: testIssuer, Timeout: 2 * time.Second})
	claims, err := p.ParseToken(signed)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if claims.Sub != testSub || claims.GetUserID() != testUsername {
		t.Fatalf("claims lost: sub=%q user=%q", claims.Sub, claims.GetUserID())
	}

	logs := buf.String()
	if !strings.Contains(logs, "Claims extracted") {
		t.Fatalf("debug log not emitted; got:\n%s", logs)
	}
	for _, secret := range []string{testSub, testUsername, signed} {
		if strings.Contains(logs, secret) {
			t.Errorf("JWT debug log leaks %q; got:\n%s", secret, logs)
		}
	}
}
