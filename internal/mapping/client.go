package mapping

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
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

// Config holds mapping service client configuration
type Config struct {
	BaseURL  string
	APIToken string
	Timeout  time.Duration
	CacheTTL time.Duration
	MockMode bool
}

// client implements the Client interface
type client struct {
	config     *Config
	httpClient *http.Client
	cache      *mappingCache
}

// mappingCache provides TTL-based caching for mapping results
type mappingCache struct {
	data map[string]*cacheEntry
	mu   sync.RWMutex
	ttl  time.Duration
}

type cacheEntry struct {
	action    string
	mapping   *Mapping
	expiresAt time.Time
}

// NewClient creates a new mapping service client
func NewClient(config *Config) Client {
	return &client{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		cache: &mappingCache{
			data: make(map[string]*cacheEntry),
			ttl:  config.CacheTTL,
		},
	}
}

// GetAction resolves (path, method) to an action using the mapping service
// Returns error if no mapping exists - caller should deny the request for security
func (c *client) GetAction(ctx context.Context, path, method string) (string, *Mapping, error) {
	if c.config.MockMode {
		return c.mockGetAction(path, method)
	}

	// Check cache first - empty string indicates cached miss
	if action, mapping := c.cache.get(path, method); action != "" {
		return action, mapping, nil
	} else if action == "" && mapping == nil {
		// This is a cached miss
		return "", nil, fmt.Errorf("no mapping found for %s %s (cached)", method, path)
	}

	// Fetch from mapping service
	mapping, err := c.fetchMapping(ctx, path, method)
	if err != nil {
		// Cache the miss and return error - no fallback for security
		c.cache.set(path, method, "", nil)
		return "", nil, fmt.Errorf("mapping service error for %s %s: %w", method, path, err)
	}

	if mapping == nil || mapping.Action == "" {
		// Cache the miss and return error - no fallback for security
		c.cache.set(path, method, "", nil)
		return "", nil, fmt.Errorf("no action mapping found for %s %s", method, path)
	}

	action := mapping.Action

	// Cache the result
	c.cache.set(path, method, action, mapping)

	return action, mapping, nil
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

// get retrieves a cached mapping
func (c *mappingCache) get(path, method string) (string, *Mapping) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(path, method)
	entry, exists := c.data[key]
	if !exists {
		return "", nil
	}

	if time.Now().After(entry.expiresAt) {
		// Entry expired, remove it
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.data, key)
		c.mu.Unlock()
		c.mu.RLock()
		return "", nil
	}

	return entry.action, entry.mapping
}

// set stores a mapping in the cache
func (c *mappingCache) set(path, method, action string, mapping *Mapping) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(path, method)
	c.data[key] = &cacheEntry{
		action:    action,
		mapping:   mapping,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// cacheKey generates a cache key for the given parameters
func (c *mappingCache) cacheKey(path, method string) string {
	return fmt.Sprintf("%s:%s", path, method)
}

// Clear removes all entries from the cache
func (c *mappingCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]*cacheEntry)
}

// Size returns the number of entries in the cache
func (c *mappingCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}
