package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
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
	Nbf               int64                  `json:"nbf"`
	Iss               string                 `json:"iss"`
	Aud               interface{}            `json:"aud"`
	jwt.RegisteredClaims
}

// RealmAccess contains realm-level roles
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key Type
	Alg string `json:"alg"` // Algorithm
	Use string `json:"use"` // Public Key Use
	N   string `json:"n"`   // Modulus
	E   string `json:"e"`   // Exponent
}

// Parser handles JWT token parsing and validation
type Parser interface {
	ParseToken(tokenString string) (*Claims, error)
}

// Config holds JWT parser configuration
type Config struct {
	JWKSEndpoint   string
	ExpectedIssuer string
	Timeout        time.Duration
}

// parser implements the Parser interface
type parser struct {
	config     *Config
	httpClient *http.Client
	jwksCache  *jwksCache
	debug      bool
}

// debugLog logs a message if debug mode is enabled
func (p *parser) debugLog(format string, args ...interface{}) {
	if p.debug {
		log.Printf("[JWT] "+format, args...)
	}
}

// jwksCache caches JWKS with automatic refresh
type jwksCache struct {
	keys      map[string]*rsa.PublicKey
	mu        sync.RWMutex
	lastFetch time.Time
	ttl       time.Duration
}

// NewParser creates a new JWT parser with JWKS fetching
func NewParser(config *Config) Parser {
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	// Check if JWT debug mode is enabled
	debug := strings.ToLower(os.Getenv("JWT_DEBUG")) == "true"

	return &parser{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		jwksCache: &jwksCache{
			keys: make(map[string]*rsa.PublicKey),
			ttl:  1 * time.Hour, // Cache JWKS for 1 hour
		},
		debug: debug,
	}
}

// ParseToken parses and validates a JWT token with full JWKS verification
func (p *parser) ParseToken(tokenString string) (*Claims, error) {
	p.debugLog("Starting JWT validation")

	// Step 1: Parse token header to get kid (without verification)
	p.debugLog("Step 1: Parsing token header to extract 'kid'")
	token, err := jwt.Parse(tokenString, nil)
	if err != nil && token == nil {
		p.debugLog("✗ Failed to parse token header: %v", err)
		return nil, fmt.Errorf("failed to parse token header: %w", err)
	}

	// Step 2: Get kid from token header
	p.debugLog("Step 2: Extracting 'kid' from token header")
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		p.debugLog("✗ Token missing 'kid' in header")
		return nil, fmt.Errorf("token missing 'kid' in header")
	}
	p.debugLog("✓ Found kid: %s", kid)

	// Step 3: Get public key from JWKS (with caching)
	p.debugLog("Step 3: Getting public key for kid=%s", kid)
	publicKey, err := p.getPublicKey(kid)
	if err != nil {
		p.debugLog("✗ Failed to get public key: %v", err)
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	p.debugLog("✓ Public key retrieved")

	// Step 4: Parse and verify token with the public key
	p.debugLog("Step 4: Verifying token signature")
	token, err = jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			p.debugLog("✗ Unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		p.debugLog("✓ Signing method validated: %v", token.Header["alg"])
		return publicKey, nil
	})

	if err != nil {
		p.debugLog("✗ Token signature verification failed: %v", err)
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	if !token.Valid {
		p.debugLog("✗ Token marked as invalid")
		return nil, fmt.Errorf("invalid token signature")
	}
	p.debugLog("✓ Token signature verified successfully")

	// Step 5: Extract and validate claims
	p.debugLog("Step 5: Extracting claims from token")
	claims, ok := token.Claims.(*Claims)
	if !ok {
		p.debugLog("✗ Failed to extract claims")
		return nil, fmt.Errorf("failed to extract claims")
	}
	p.debugLog("✓ Claims extracted - sub=%s, iss=%s, exp=%d", claims.Sub, claims.Iss, claims.Exp)

	// Step 6: Validate issuer
	p.debugLog("Step 6: Validating issuer")
	if p.config.ExpectedIssuer != "" && claims.Iss != p.config.ExpectedIssuer {
		p.debugLog("✗ Invalid issuer: expected '%s', got '%s'", p.config.ExpectedIssuer, claims.Iss)
		return nil, fmt.Errorf("invalid issuer: expected '%s', got '%s'", p.config.ExpectedIssuer, claims.Iss)
	}
	p.debugLog("✓ Issuer validated: %s", claims.Iss)

	// Step 7: Validate time-based claims
	p.debugLog("Step 7: Validating time-based claims")
	now := time.Now().Unix()

	// Check expiration
	if claims.Exp > 0 && now > claims.Exp {
		p.debugLog("✗ Token expired: exp=%d, now=%d", claims.Exp, now)
		return nil, fmt.Errorf("token is expired")
	}
	p.debugLog("✓ Token not expired: exp=%d, now=%d", claims.Exp, now)

	// Check not before
	if claims.Nbf > 0 && now < claims.Nbf {
		p.debugLog("✗ Token used before valid time: nbf=%d, now=%d", claims.Nbf, now)
		return nil, fmt.Errorf("token used before valid time")
	}
	if claims.Nbf > 0 {
		p.debugLog("✓ Token valid time check passed: nbf=%d, now=%d", claims.Nbf, now)
	}

	p.debugLog("✅ JWT validation completed successfully")
	return claims, nil
}

// getPublicKey retrieves a public key by kid, using cache when available
func (p *parser) getPublicKey(kid string) (*rsa.PublicKey, error) {
	// Check cache first
	p.jwksCache.mu.RLock()
	if key, exists := p.jwksCache.keys[kid]; exists && time.Since(p.jwksCache.lastFetch) < p.jwksCache.ttl {
		p.jwksCache.mu.RUnlock()
		p.debugLog("✓ JWKS cache HIT for kid=%s (age: %s)", kid, time.Since(p.jwksCache.lastFetch).Round(time.Second))
		return key, nil
	}
	p.jwksCache.mu.RUnlock()

	p.debugLog("✗ JWKS cache MISS for kid=%s - fetching from endpoint", kid)

	// Fetch fresh JWKS
	if err := p.fetchJWKS(); err != nil {
		p.debugLog("✗ Failed to fetch JWKS: %v", err)
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Try to get key from updated cache
	p.jwksCache.mu.RLock()
	key, exists := p.jwksCache.keys[kid]
	p.jwksCache.mu.RUnlock()

	if !exists {
		p.debugLog("✗ Key with kid '%s' not found in fetched JWKS", kid)
		return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
	}

	p.debugLog("✓ Public key retrieved from fresh JWKS")
	return key, nil
}

// fetchJWKS fetches JWKS from the configured endpoint and updates cache
func (p *parser) fetchJWKS() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.config.JWKSEndpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("JWKS endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Update cache with new keys
	p.jwksCache.mu.Lock()
	defer p.jwksCache.mu.Unlock()

	p.jwksCache.keys = make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue // Only support RSA keys
		}

		publicKey, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			// Log error but continue with other keys
			continue
		}

		p.jwksCache.keys[jwk.Kid] = publicKey
	}

	p.jwksCache.lastFetch = time.Now()

	if len(p.jwksCache.keys) == 0 {
		return fmt.Errorf("no valid RSA keys found in JWKS")
	}

	return nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key
func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}

	return publicKey, nil
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
