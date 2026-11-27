package logsafe

import "testing"

// Synthetic CPFs only (valid check digits, no real person).
const (
	syntheticCPF  = "12345678909"
	formattedCPF2 = "123.456.789-09"
)

func TestPathMasksCPF(t *testing.T) {
	cases := map[string]string{
		"/rmi/v1/citizen/" + syntheticCPF:                     "/rmi/v1/citizen/[CPF]",
		"/rmi/v1/citizen/" + syntheticCPF + "/wallet":         "/rmi/v1/citizen/[CPF]/wallet",
		"/go/api/v1/enrollments/user/" + syntheticCPF:         "/go/api/v1/enrollments/user/[CPF]",
		"/api/v1/citizen/" + formattedCPF2 + "/phone":         "/api/v1/citizen/[CPF]/phone",
		"/api/v1/citizen/123456789-09":                        "/api/v1/citizen/[CPF]",
		"/api/v1/x/cpf-" + syntheticCPF + ".json":             "/api/v1/x/cpf-[CPF].json",
		"/a/" + syntheticCPF + "/b/" + syntheticCPF:           "/a/[CPF]/b/[CPF]",
		"https://services.example.test/c/" + syntheticCPF:     "https://services.example.test/c/[CPF]",
		"/a/" + syntheticCPF + "-" + syntheticCPF:             "/a/[CPF]-[CPF]",
		"/rmi/v1/citizen/" + syntheticCPF + "?cpf=[REDACTED]": "/rmi/v1/citizen/[CPF]?cpf=[REDACTED]",
	}
	for in, want := range cases {
		if got := Path(in); got != want {
			t.Errorf("Path(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPathKeepsOtherNumbers(t *testing.T) {
	for _, keep := range []string{
		"",
		"/health",
		"/api/v1/categories",
		"/api/v1/services/42",
		"/api/v1/x/1234567890",     // 10 digits
		"/api/v1/x/123456789012",   // 12 digits
		"/api/v1/x/12345678000195", // 14 digits (CNPJ)
		"/api/v1/x/1795820870847",  // timestamp in ms
		"/api/v1/report/2026-11-27",
		"/api/v2.1.3/docs",
		"/api/v1/x/550e8400-e29b-41d4-a716-446655440000",
	} {
		if got := Path(keep); got != keep {
			t.Errorf("Path(%q) = %q, want it unchanged", keep, got)
		}
	}
}
