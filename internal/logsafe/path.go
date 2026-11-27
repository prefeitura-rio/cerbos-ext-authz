// Package logsafe prepares request data for the logs and the spans.
package logsafe

import "regexp"

// MaskedCPF replaces a CPF (or another 11-digit identifier) found in a path.
const MaskedCPF = "[CPF]"

var (
	// numericRun is a run of digits, possibly with the "." and "-" of a
	// formatted CPF (123.456.789-09) between them.
	numericRun = regexp.MustCompile(`[0-9](?:[0-9.\-]*[0-9])?`)
	// formattedCPF is a whole run in the CPF format, punctuated or not.
	formattedCPF = regexp.MustCompile(`^[0-9]{3}\.?[0-9]{3}\.?[0-9]{3}-?[0-9]{2}$`)
	digits       = regexp.MustCompile(`[0-9]+`)
)

// Path returns the path (or URL) with every CPF in it masked. Services behind
// the ext-authz carry the citizen's CPF in the path (app-rmi
// /v1/citizen/<cpf>/..., app-go-api /enrollments/user/<cpf>), so the path is
// never logged nor put in a span as is. Any run of exactly 11 digits is
// masked, as is a punctuated CPF; shorter or longer numbers (ids, dates,
// timestamps) are kept. The authorization itself always uses the real path.
func Path(path string) string {
	return numericRun.ReplaceAllStringFunc(path, func(run string) string {
		if formattedCPF.MatchString(run) {
			return MaskedCPF
		}
		return digits.ReplaceAllStringFunc(run, func(d string) string {
			if len(d) == 11 {
				return MaskedCPF
			}
			return d
		})
	})
}
