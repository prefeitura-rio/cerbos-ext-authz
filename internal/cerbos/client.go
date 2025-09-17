package cerbos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client handles Cerbos PDP authorization requests
type Client interface {
	CheckResources(ctx context.Context, request *CheckResourcesRequest) (*CheckResourcesResponse, error)
}

// CheckResourcesRequest represents a Cerbos check resources request
type CheckResourcesRequest struct {
	RequestID string     `json:"requestId"`
	Principal Principal  `json:"principal"`
	Resources []Resource `json:"resources"`
}

// Principal represents the user/entity making the request
type Principal struct {
	ID            string                 `json:"id"`
	Roles         []string               `json:"roles"`
	PolicyVersion string                 `json:"policyVersion"`
	Attr          map[string]interface{} `json:"attr"`
}

// Resource represents a resource being accessed
type Resource struct {
	Resource ResourceInfo `json:"resource"`
	Actions  []string     `json:"actions"`
}

// ResourceInfo contains resource metadata
type ResourceInfo struct {
	Kind string                 `json:"kind"`
	ID   string                 `json:"id"`
	Attr map[string]interface{} `json:"attr"`
}

// CheckResourcesResponse represents a Cerbos check resources response
type CheckResourcesResponse struct {
	RequestID string                   `json:"requestId"`
	Results   []ResourceActionResponse `json:"results"`
}

// ResourceActionResponse represents the response for a specific resource
type ResourceActionResponse struct {
	Resource ResourceInfo      `json:"resource"`
	Actions  map[string]string `json:"actions"`
}

// ActionDecision represents the decision for a specific action
type ActionDecision struct {
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
}

// Config holds Cerbos client configuration
type Config struct {
	Endpoint string
	Timeout  time.Duration
	MockMode bool
}

// client implements the Client interface
type client struct {
	config     *Config
	httpClient *http.Client
}

// NewClient creates a new Cerbos client
func NewClient(config *Config) Client {
	return &client{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// CheckResources performs a Cerbos policy check
func (c *client) CheckResources(ctx context.Context, request *CheckResourcesRequest) (*CheckResourcesResponse, error) {
	if c.config.MockMode {
		return c.mockCheck(request)
	}

	// Serialize request
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.config.Endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call Cerbos: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cerbos returned status %d", resp.StatusCode)
	}

	// Parse response
	var response CheckResourcesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

// mockCheck provides mock responses for testing
func (c *client) mockCheck(request *CheckResourcesRequest) (*CheckResourcesResponse, error) {
	// Default to allow for mock mode
	responses := make([]ResourceActionResponse, len(request.Resources))

	for i, resource := range request.Resources {
		actions := make(map[string]string)
		for _, action := range resource.Actions {
			// Mock logic: deny for anonymous users, allow for authenticated users
			result := "EFFECT_ALLOW"
			if request.Principal.ID == "anonymous" {
				result = "EFFECT_DENY"
			}

			actions[action] = result
		}

		responses[i] = ResourceActionResponse{
			Resource: resource.Resource,
			Actions:  actions,
		}
	}

	return &CheckResourcesResponse{
		RequestID: request.RequestID,
		Results:   responses,
	}, nil
}

// IsAllowed checks if an action is allowed based on the response
func (r *CheckResourcesResponse) IsAllowed(action string) bool {
	if len(r.Results) == 0 {
		return false
	}

	decision, exists := r.Results[0].Actions[action]
	if !exists {
		return false
	}

	return decision == "EFFECT_ALLOW"
}

// GetDecision returns the decision for a specific action
func (r *CheckResourcesResponse) GetDecision(action string) string {
	if len(r.Results) == 0 {
		return ""
	}

	decision, exists := r.Results[0].Actions[action]
	if !exists {
		return ""
	}

	return decision
}
