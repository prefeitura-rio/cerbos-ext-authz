package service

import (
	"fmt"
	"strings"
	"testing"
)

func TestRequestLogFieldsNeverCarryTheCredential(t *testing.T) {
	const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJwcmVmZXJyZWRfdXNlcm5hbWUiOiIxMjM0NTY3ODkwMSJ9.c2lnbmF0dXJl"
	fields := requestLogFields("req_1", &AuthorizationRequest{AuthHeader: "Bearer " + jwt, Method: "GET", Path: "/v1/citizen/me", Host: "services.example.test"})
	if dump := fmt.Sprint(fields); strings.Contains(dump, jwt) {
		t.Fatalf("request log fields leak the JWT: %s", dump)
	}
	if fields["auth_header_present"] != true || fields["path"] != "/v1/citizen/me" {
		t.Fatalf("request log fields lost the request details: %v", fields)
	}
	if requestLogFields("req_2", &AuthorizationRequest{})["auth_header_present"] != false {
		t.Fatal("a request without credential must log auth_header_present=false")
	}
}
