package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// principalLogKey keys the principal pseudonyms. It is random per process, so
// a pseudonym is stable across the log lines of one pod (requests of the same
// user can be correlated) but cannot be reversed by hashing every CPF.
var principalLogKey = newPrincipalLogKey()

func newPrincipalLogKey() []byte {
	key := make([]byte, 32)
	// Since Go 1.24 crypto/rand.Read never returns an error: it crashes the
	// program instead, so the key is never left empty.
	_, _ = rand.Read(key)
	return key
}

// PrincipalForLog identifies a principal in the logs without exposing it: the
// principal is the JWT preferred_username, which on gov.br is the citizen's CPF.
// The non-personal principals the service itself assigns stay readable.
func PrincipalForLog(principalID string) string {
	switch principalID {
	case "":
		return ""
	case "anonymous", "unknown":
		return principalID
	}
	mac := hmac.New(sha256.New, principalLogKey)
	mac.Write([]byte(principalID))
	return "user:" + hex.EncodeToString(mac.Sum(nil))[:16]
}
