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
	CacheTTL       time.Duration // Normal cache TTL (default: 1 hour)
	GraceTTL       time.Duration // Grace period for stale cache (default: 24 hours)
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

// jwksCache caches JWKS with automatic refresh and stale-while-revalidate support
type jwksCache struct {
	keys      map[string]*rsa.PublicKey
	mu        sync.RWMutex
	lastFetch time.Time
	ttl       time.Duration // Normal TTL - triggers refresh
	graceTTL  time.Duration // Grace period - allows stale cache on fetch failure
}

// NewParser creates a new JWT parser with JWKS fetching
func NewParser(config *Config) Parser {
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}

	// Set default cache TTLs if not configured
	if config.CacheTTL == 0 {
		config.CacheTTL = 1 * time.Hour // Default: 1 hour
	}
	if config.GraceTTL == 0 {
		config.GraceTTL = 24 * time.Hour // Default: 24 hours
	}

	// Check if JWT debug mode is enabled
	debug := strings.ToLower(os.Getenv("JWT_DEBUG")) == "true"

	return &parser{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		jwksCache: &jwksCache{
			keys:     make(map[string]*rsa.PublicKey),
			ttl:      config.CacheTTL,
			graceTTL: config.GraceTTL,
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
	// sub and the other identity claims identify the citizen: never logged.
	p.debugLog("✓ Claims extracted - iss=%s, exp=%d", claims.Iss, claims.Exp)

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
// Implements stale-while-revalidate pattern for resilience
func (p *parser) getPublicKey(kid string) (*rsa.PublicKey, error) {
	// Read current cache state
	p.jwksCache.mu.RLock()
	cachedKey, keyExists := p.jwksCache.keys[kid]
	cacheAge := time.Since(p.jwksCache.lastFetch)
	p.jwksCache.mu.RUnlock()

	// FRESH CACHE: Return immediately if within normal TTL
	if keyExists && cacheAge < p.jwksCache.ttl {
		p.debugLog("✓ JWKS cache HIT for kid=%s (age: %s)", kid, cacheAge.Round(time.Second))
		return cachedKey, nil
	}

	// STALE CACHE or MISS: Attempt to refresh
	if keyExists {
		p.debugLog("⚠ JWKS cache STALE for kid=%s (age: %s, ttl: %s) - attempting refresh",
			kid, cacheAge.Round(time.Second), p.jwksCache.ttl)
	} else {
		p.debugLog("✗ JWKS cache MISS for kid=%s - fetching from endpoint", kid)
	}

	// Try to fetch fresh JWKS
	err := p.fetchJWKS()
	if err != nil {
		// JWKS fetch failed
		if keyExists {
			// Check if we're still within grace period
			if cacheAge < p.jwksCache.graceTTL {
				// STALE-WHILE-REVALIDATE: Use stale cache as fallback
				p.debugLog("⚠ JWKS fetch failed, using STALE cache for kid=%s (age: %s, grace: %s): %v",
					kid, cacheAge.Round(time.Second), p.jwksCache.graceTTL, err)
				log.Printf("[JWT] ⚠ WARNING: JWKS endpoint unreachable, using stale cache (age: %s) - this should be investigated",
					cacheAge.Round(time.Second))
				return cachedKey, nil // Return stale key instead of failing
			}
			// Beyond grace period - cannot use stale cache
			p.debugLog("✗ JWKS fetch failed and cache beyond grace period (age: %s, grace: %s): %v",
				cacheAge.Round(time.Second), p.jwksCache.graceTTL, err)
			return nil, fmt.Errorf("JWKS cache expired beyond grace period and fetch failed: %w", err)
		}

		// No cached key available - must fail
		p.debugLog("✗ Failed to fetch JWKS and no cached key available: %v", err)
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Refresh succeeded - get updated key from cache
	p.jwksCache.mu.RLock()
	key, exists := p.jwksCache.keys[kid]
	p.jwksCache.mu.RUnlock()

	if !exists {
		// Key not found in fresh JWKS (key rotation may have removed it)
		if keyExists {
			// Use the old key we had cached (it might still be valid)
			p.debugLog("⚠ Kid '%s' not in fresh JWKS, using previously cached key", kid)
			log.Printf("[JWT] ⚠ WARNING: Kid '%s' disappeared from JWKS - using stale cache, key rotation may be in progress", kid)
			return cachedKey, nil
		}
		p.debugLog("✗ Key with kid '%s' not found in fetched JWKS", kid)
		return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
	}

	p.debugLog("✓ JWKS refreshed successfully for kid=%s", kid)
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

	// Parse new keys from JWKS
	newKeys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue // Only support RSA keys
		}

		publicKey, err := jwkToRSAPublicKey(jwk)
		if err != nil {
			// Log error but continue with other keys
			p.debugLog("⚠ Failed to parse JWK with kid=%s: %v", jwk.Kid, err)
			continue
		}

		newKeys[jwk.Kid] = publicKey
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("no valid RSA keys found in JWKS")
	}

	// Update cache with new keys (replaces all keys)
	p.jwksCache.mu.Lock()
	p.jwksCache.keys = newKeys
	p.jwksCache.lastFetch = time.Now()
	p.jwksCache.mu.Unlock()

	p.debugLog("✓ JWKS cache updated with %d keys", len(newKeys))
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
