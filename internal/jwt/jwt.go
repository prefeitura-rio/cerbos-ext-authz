package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT claims with common Keycloak fields
type Claims struct {
	Sub               string                 `json:"sub"`
	PreferredUsername string                 `json:"preferred_username"`
	Roles             []string               `json:"roles"`
	RealmAccess       *RealmAccess           `json:"realm_access"`
	ResourceAccess    map[string]interface{} `json:"resource_access"`
	Exp               int64                  `json:"exp"`
	Iat               int64                  `json:"iat"`
	Iss               string                 `json:"iss"`
	Aud               interface{}            `json:"aud"`
	jwt.RegisteredClaims
}

// RealmAccess contains realm-level roles
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// Parser handles JWT token parsing and validation
type Parser interface {
	ParseToken(tokenString string) (*Claims, error)
	ParseWithoutVerification(tokenString string) (*Claims, error)
}

// Config holds JWT parser configuration
type Config struct {
	VerifySignature bool
	JWKSEndpoint    string
	PublicKey       *rsa.PublicKey
}

// parser implements the Parser interface
type parser struct {
	config *Config
}

// NewParser creates a new JWT parser
func NewParser(config *Config) Parser {
	return &parser{
		config: config,
	}
}

// ParseToken parses and validates a JWT token
func (p *parser) ParseToken(tokenString string) (*Claims, error) {
	if !p.config.VerifySignature {
		return p.ParseWithoutVerification(tokenString)
	}

	// Parse with verification
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the public key for verification
		if p.config.PublicKey != nil {
			return p.config.PublicKey, nil
		}

		// If no public key is provided, we can't verify
		return nil, fmt.Errorf("no public key configured for JWT verification")
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims")
	}

	return claims, nil
}

// ParseWithoutVerification parses a JWT token without signature verification
func (p *parser) ParseWithoutVerification(tokenString string) (*Claims, error) {
	// Split token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	// Parse claims
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return &claims, nil
}

// GetUserID extracts user ID from claims (prefer preferred_username, fallback to sub)
func (c *Claims) GetUserID() string {
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	return c.Sub
}

// GetRoles extracts roles from claims (try direct roles field, then realm_access.roles)
func (c *Claims) GetRoles() []string {
	// Direct roles field
	if len(c.Roles) > 0 {
		return c.Roles
	}

	// Keycloak realm_access.roles
	if c.RealmAccess != nil && len(c.RealmAccess.Roles) > 0 {
		return c.RealmAccess.Roles
	}

	return []string{}
}

// IsExpired checks if the token is expired
func (c *Claims) IsExpired() bool {
	if c.Exp == 0 {
		return false // No expiration set
	}
	return time.Now().Unix() > c.Exp
}

// IsAuthenticated checks if this represents an authenticated user
func (c *Claims) IsAuthenticated() bool {
	return c.GetUserID() != "" && c.GetUserID() != "anonymous"
}

// ExtractBearerToken extracts the Bearer token from an Authorization header
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}
