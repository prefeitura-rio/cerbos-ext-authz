package mapping

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client handles mapping service requests to resolve (path, method) -> action
type Client interface {
	GetAction(ctx context.Context, path, method string) (string, *Mapping, error)
}

// Mapping represents a mapping response from the mapping service
type Mapping struct {
	Action     string                 `json:"action"`
	Path       string                 `json:"path"`
	Method     string                 `json:"method"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// RedisMapping represents the mapping data structure stored in Redis
type RedisMapping struct {
	ID          int    `json:"id"`
	Method      string `json:"method"`
	PathPattern string `json:"path_pattern"`
	ActionID    int    `json:"action_id"`
	ActionName  string `json:"action_name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// Config holds mapping service client configuration
type Config struct {
	// Redis configuration
	RedisSentinelHosts   string
	RedisSentinelService string
	RedisPassword        string

	// Legacy HTTP configuration (for fallback if needed)
	BaseURL  string
	APIToken string
	Timeout  time.Duration

	MockMode bool
}

// client implements the Client interface
type client struct {
	config      *Config
	redisClient *redis.Client
	httpClient  *http.Client // Kept for legacy/fallback support
}

// NewClient creates a new mapping service client
func NewClient(config *Config) Client {
	// Initialize Redis client if configuration is provided
	var redisClient *redis.Client
	if config.RedisSentinelHosts != "" && config.RedisSentinelService != "" {
		// Parse sentinel hosts
		hosts := strings.Split(config.RedisSentinelHosts, ",")
		for i, host := range hosts {
			hosts[i] = strings.TrimSpace(host)
		}

		redisClient = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    config.RedisSentinelService,
			SentinelAddrs: hosts,
			Password:      config.RedisPassword,
			DB:            0,
		})
		log.Printf("[MAPPING] Redis client initialized: sentinel=%s, hosts=%v",
			config.RedisSentinelService, hosts)
	}

	return &client{
		config:      config,
		redisClient: redisClient,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// GetAction resolves (path, method) to an action using Redis mappings
// Returns error if no mapping exists - caller should deny the request for security
func (c *client) GetAction(ctx context.Context, path, method string) (string, *Mapping, error) {
	if c.config.MockMode {
		return c.mockGetAction(path, method)
	}

	// If Redis is not configured, fail with clear error
	if c.redisClient == nil {
		return "", nil, fmt.Errorf("Redis mappings not configured - service unavailable")
	}

	// Try Redis lookup directly (no local caching needed since Redis is already fast)
	action, mapping, err := c.getActionFromRedis(ctx, path, method)
	if err != nil {
		return "", nil, fmt.Errorf("mapping lookup failed for %s %s: %w", method, path, err)
	}

	if action == "" {
		return "", nil, fmt.Errorf("no mapping found for %s %s", method, path)
	}

	return action, mapping, nil
}

// getActionFromRedis implements the Redis lookup algorithm from the spec
func (c *client) getActionFromRedis(ctx context.Context, path, method string) (string, *Mapping, error) {
	// Step 1: Try fast path lookup (cache)
	cacheKey := fmt.Sprintf("heimdall:mappings:lookup:%s:%s", method, path)
	log.Printf("[MAPPING] Cache lookup: %s", cacheKey)

	mappingID, err := c.redisClient.Get(ctx, cacheKey).Result()

	if err == nil && mappingID != "" {
		log.Printf("[MAPPING] ✓ Cache HIT: %s %s -> mapping_%s", method, path, mappingID)
		// Step 2: Get mapping details from cache hit
		return c.getMappingDetails(ctx, mappingID, path, method)
	}

	// Step 3: Pattern matching fallback
	log.Printf("[MAPPING] ✗ Cache MISS: %s %s - trying pattern matching", method, path)
	return c.patternMatchingFallback(ctx, path, method)
}

// getMappingDetails retrieves mapping details by ID from Redis
func (c *client) getMappingDetails(ctx context.Context, mappingID, originalPath, originalMethod string) (string, *Mapping, error) {
	log.Printf("[MAPPING] Fetching details: heimdall:mappings:all[mapping_%s]", mappingID)

	mappingData, err := c.redisClient.HGet(ctx, "heimdall:mappings:all", mappingID).Result()
	if err != nil {
		log.Printf("[MAPPING] ✗ Failed to get mapping details for ID %s: %v", mappingID, err)
		return "", nil, fmt.Errorf("failed to get mapping details for ID %s: %w", mappingID, err)
	}

	var redisMapping RedisMapping
	if err := json.Unmarshal([]byte(mappingData), &redisMapping); err != nil {
		log.Printf("[MAPPING] ✗ Failed to parse mapping data for ID %s: %v", mappingID, err)
		return "", nil, fmt.Errorf("failed to parse mapping data for ID %s: %w", mappingID, err)
	}

	// Convert Redis mapping to our Mapping struct
	mapping := &Mapping{
		Action: redisMapping.ActionName,
		Path:   originalPath,
		Method: originalMethod,
		Attributes: map[string]interface{}{
			"mapping_id":   redisMapping.ID,
			"path_pattern": redisMapping.PathPattern,
			"action_id":    redisMapping.ActionID,
			"description":  redisMapping.Description,
		},
	}

	log.Printf("[MAPPING] ✓ Resolved: %s %s -> %s (pattern: %s)", originalMethod, originalPath, redisMapping.ActionName, redisMapping.PathPattern)
	return redisMapping.ActionName, mapping, nil
}

// patternMatchingFallback implements pattern matching when cache misses
func (c *client) patternMatchingFallback(ctx context.Context, path, method string) (string, *Mapping, error) {
	// Step 1: Get all patterns for the HTTP method (ordered by specificity)
	patternKey := fmt.Sprintf("heimdall:mappings:patterns:%s", method)
	log.Printf("[MAPPING] Loading patterns: %s", patternKey)

	mappingIDs, err := c.redisClient.LRange(ctx, patternKey, 0, -1).Result()
	if err != nil {
		log.Printf("[MAPPING] ✗ Failed to get patterns for method %s: %v", method, err)
		return "", nil, fmt.Errorf("failed to get patterns for method %s: %w", method, err)
	}

	log.Printf("[MAPPING] Testing %d patterns for: %s %s", len(mappingIDs), method, path)

	// Step 2: Test each pattern until match found
	for i, mappingID := range mappingIDs {
		// Get the mapping details
		mappingData, err := c.redisClient.HGet(ctx, "heimdall:mappings:all", mappingID).Result()
		if err != nil {
			log.Printf("[MAPPING] Pattern %d/%d: ✗ Failed to get data for mapping_%s", i+1, len(mappingIDs), mappingID)
			continue
		}

		var redisMapping RedisMapping
		if err := json.Unmarshal([]byte(mappingData), &redisMapping); err != nil {
			log.Printf("[MAPPING] Pattern %d/%d: ✗ Failed to parse data for mapping_%s", i+1, len(mappingIDs), mappingID)
			continue
		}

		// Test if request path matches the pattern
		log.Printf("[MAPPING] Pattern %d/%d: Testing '%s' against '%s'", i+1, len(mappingIDs), path, redisMapping.PathPattern)
		matched, err := regexp.MatchString(redisMapping.PathPattern, path)
		if err != nil {
			log.Printf("[MAPPING] Pattern %d/%d: ✗ Invalid regex '%s': %v", i+1, len(mappingIDs), redisMapping.PathPattern, err)
			continue
		}

		if matched {
			log.Printf("[MAPPING] Pattern %d/%d: ✓ MATCH! '%s' -> %s", i+1, len(mappingIDs), redisMapping.PathPattern, redisMapping.ActionName)

			// Cache the result for future lookups (5 minute TTL as per spec)
			cacheKey := fmt.Sprintf("heimdall:mappings:lookup:%s:%s", method, path)
			log.Printf("[MAPPING] Caching result: %s -> mapping_%s (5min TTL)", cacheKey, mappingID)
			c.redisClient.SetEx(ctx, cacheKey, mappingID, 5*time.Minute)

			// Convert to our Mapping struct
			mapping := &Mapping{
				Action: redisMapping.ActionName,
				Path:   path,
				Method: method,
				Attributes: map[string]interface{}{
					"mapping_id":   redisMapping.ID,
					"path_pattern": redisMapping.PathPattern,
					"action_id":    redisMapping.ActionID,
					"description":  redisMapping.Description,
				},
			}

			return redisMapping.ActionName, mapping, nil
		} else {
			log.Printf("[MAPPING] Pattern %d/%d: ✗ No match", i+1, len(mappingIDs))
		}
	}

	// No match found
	log.Printf("[MAPPING] ✗ No pattern matches found for %s %s", method, path)
	return "", nil, nil
}

// fetchMapping calls the mapping service to get the mapping
func (c *client) fetchMapping(ctx context.Context, path, method string) (*Mapping, error) {
	// Build URL with query parameters
	baseURL, err := url.Parse(c.config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	mappingURL := baseURL.ResolveReference(&url.URL{Path: "/api/v1/mappings"})

	// Add query parameters
	params := url.Values{}
	params.Add("path", path)
	params.Add("method", method)
	mappingURL.RawQuery = params.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", mappingURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header if token is provided
	if c.config.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.APIToken)
		// Debug logging for API token
		log.Printf("[DEBUG] Mapping service call with API token: Bearer %s", c.config.APIToken)
	} else {
		log.Printf("[DEBUG] No API token configured for mapping service")
	}

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call mapping service: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Handle different types of 404 responses
	if resp.StatusCode == http.StatusNotFound {
		// Try to parse the response body to distinguish between endpoint not found vs mapping not found
		var errorResponse struct {
			Error      string `json:"error"`
			StatusCode int    `json:"status_code"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err == nil {
			// Successfully parsed JSON error response - this means mapping not found
			return nil, nil
		}

		// Failed to parse JSON - likely endpoint not found (wrong URL)
		return nil, fmt.Errorf("mapping service endpoint not found (404) - check URL path")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mapping service returned status %d", resp.StatusCode)
	}

	// Parse response
	var mapping Mapping
	if err := json.NewDecoder(resp.Body).Decode(&mapping); err != nil {
		return nil, fmt.Errorf("failed to decode mapping response: %w", err)
	}

	return &mapping, nil
}

// mockGetAction provides mock responses for testing
func (c *client) mockGetAction(path, method string) (string, *Mapping, error) {
	// Mock logic based on common patterns
	var action string

	switch {
	case method == "GET" && path == "/health":
		action = "health:check"
	case method == "GET":
		action = "api:read"
	case method == "POST":
		action = "api:create"
	case method == "PUT" || method == "PATCH":
		action = "api:update"
	case method == "DELETE":
		action = "api:delete"
	default:
		action = "api:call"
	}

	mapping := &Mapping{
		Action: action,
		Path:   path,
		Method: method,
		Attributes: map[string]interface{}{
			"mock": true,
		},
	}

	return action, mapping, nil
}
