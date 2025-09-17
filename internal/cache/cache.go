package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Cache interface for storing validation results
type Cache interface {
	Get(ctx context.Context, key string) (*ValidationResult, error)
	Set(ctx context.Context, key string, result *ValidationResult, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
	GetStats() Stats
}

// ValidationResult represents a cached validation result
type ValidationResult struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score,omitempty"`
	Action      string    `json:"action,omitempty"`
	ChallengeTS string    `json:"challenge_ts,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	ErrorCodes  []string  `json:"error_codes,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// Stats represents cache statistics
type Stats struct {
	Hits   int64 `json:"hits"`
	Misses int64 `json:"misses"`
	Size   int64 `json:"size"`
}

// Config holds cache configuration
type Config struct {
	Type          string        // "memory" or "redis"
	RedisURL      string        // Redis connection URL
	DefaultTTL    time.Duration // Default TTL for successful validations
	FailedTTL     time.Duration // TTL for failed validations
	MaxMemorySize int           // Maximum number of items in memory cache
}

// memoryCache implements in-memory caching
type memoryCache struct {
	config Config
	data   map[string]*cacheEntry
	mu     sync.RWMutex
	stats  Stats
}

type cacheEntry struct {
	result    *ValidationResult
	expiresAt time.Time
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(config Config) Cache {
	return &memoryCache{
		config: config,
		data:   make(map[string]*cacheEntry),
	}
}

func (c *memoryCache) Get(ctx context.Context, key string) (*ValidationResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		c.stats.Misses++
		return nil, fmt.Errorf("cache miss")
	}

	if time.Now().After(entry.expiresAt) {
		// Expired entry, remove it
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.data, key)
		c.mu.Unlock()
		c.mu.RLock()
		c.stats.Misses++
		return nil, fmt.Errorf("cache miss (expired)")
	}

	c.stats.Hits++
	return entry.result, nil
}

func (c *memoryCache) Set(ctx context.Context, key string, result *ValidationResult, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict items
	if int64(len(c.data)) >= int64(c.config.MaxMemorySize) {
		c.evictOldest()
	}

	entry := &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}

	c.data[key] = entry
	c.stats.Size = int64(len(c.data))

	return nil
}

func (c *memoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, key)
	c.stats.Size = int64(len(c.data))
	return nil
}

func (c *memoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]*cacheEntry)
	c.stats.Size = 0
	return nil
}

func (c *memoryCache) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return Stats{
		Hits:   c.stats.Hits,
		Misses: c.stats.Misses,
		Size:   c.stats.Size,
	}
}

func (c *memoryCache) evictOldest() {
	// Simple LRU: remove the oldest entry
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.data {
		if oldestKey == "" || entry.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiresAt
		}
	}

	if oldestKey != "" {
		delete(c.data, oldestKey)
	}
}

// redisCache implements Redis caching
type redisCache struct {
	config Config
	client *redis.Client
	stats  Stats
	mu     sync.RWMutex
}

// NewRedisCache creates a new Redis cache
func NewRedisCache(config Config) (Cache, error) {
	opts, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &redisCache{
		config: config,
		client: client,
	}, nil
}

func (c *redisCache) Get(ctx context.Context, key string) (*ValidationResult, error) {
	data, err := c.client.Get(ctx, c.hashKey(key)).Result()
	if err != nil {
		if err == redis.Nil {
			c.mu.Lock()
			c.stats.Misses++
			c.mu.Unlock()
			return nil, fmt.Errorf("cache miss")
		}
		return nil, fmt.Errorf("failed to get from Redis: %w", err)
	}

	var result ValidationResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached result: %w", err)
	}

	c.mu.Lock()
	c.stats.Hits++
	c.mu.Unlock()

	return &result, nil
}

func (c *redisCache) Set(ctx context.Context, key string, result *ValidationResult, ttl time.Duration) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	err = c.client.Set(ctx, c.hashKey(key), data, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set in Redis: %w", err)
	}

	return nil
}

func (c *redisCache) Delete(ctx context.Context, key string) error {
	err := c.client.Del(ctx, c.hashKey(key)).Err()
	if err != nil {
		return fmt.Errorf("failed to delete from Redis: %w", err)
	}
	return nil
}

func (c *redisCache) Clear(ctx context.Context) error {
	// Note: This will clear ALL keys in the database
	// In production, you might want to use a more targeted approach
	err := c.client.FlushDB(ctx).Err()
	if err != nil {
		return fmt.Errorf("failed to clear Redis: %w", err)
	}
	return nil
}

func (c *redisCache) GetStats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return Stats{
		Hits:   c.stats.Hits,
		Misses: c.stats.Misses,
		Size:   c.stats.Size, // Redis doesn't provide easy size counting
	}
}

func (c *redisCache) hashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// NewCache creates a new Redis cache
func NewCache(config Config) (Cache, error) {
	return NewRedisCache(config)
}

// GenerateCacheKey generates a cache key for a token
func GenerateCacheKey(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
