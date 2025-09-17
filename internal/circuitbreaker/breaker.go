package circuitbreaker

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// State represents the circuit breaker state
type State int

const (
	StateClosed State = iota
	StateHalfOpen
	StateOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half_open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// Config holds circuit breaker configuration
type Config struct {
	FailureThreshold    int
	RecoveryTime        time.Duration
	HalfOpenMaxRequests int
}

// Breaker implements the circuit breaker pattern
type Breaker struct {
	config Config
	state  State
	mu     sync.RWMutex

	// Failure tracking
	failureCount    int
	lastFailureTime time.Time

	// Half-open tracking
	halfOpenRequests int

	// Metrics
	totalRequests int64
	totalFailures int64
	totalTimeouts int64
	stateChanges  int64
}

// NewBreaker creates a new circuit breaker
func NewBreaker(config Config) *Breaker {
	return &Breaker{
		config:          config,
		state:           StateClosed,
		lastFailureTime: time.Now(), // Initialize with current time
	}
}

// Execute executes a function with circuit breaker protection
func (b *Breaker) Execute(ctx context.Context, fn func() error) error {
	// Safety check
	if b == nil {
		return fmt.Errorf("circuit breaker is nil")
	}

	// Check if we can execute
	if !b.canExecute() {
		return fmt.Errorf("circuit breaker is open")
	}

	// Handle transition from open to half-open if needed
	b.mu.Lock()
	if b.state == StateOpen {
		b.transitionToHalfOpen()
	}
	b.mu.Unlock()

	b.recordRequest()

	err := fn()
	if err != nil {
		b.recordFailure()
		return err
	}

	b.recordSuccess()
	return nil
}

// canExecute checks if the circuit breaker allows execution
func (b *Breaker) canExecute() bool {
	if b == nil {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	switch b.state {
	case StateClosed:
		return true
	case StateHalfOpen:
		return b.halfOpenRequests < b.config.HalfOpenMaxRequests
	case StateOpen:
		// Check if recovery time has passed
		if time.Since(b.lastFailureTime) >= b.config.RecoveryTime {
			// We need to transition to half-open, but we can't do it here
			// because we're holding a read lock. Let's return true and let
			// the caller handle the transition.
			return true
		}
		return false
	default:
		return false
	}
}

// recordRequest records a request attempt
func (b *Breaker) recordRequest() {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.totalRequests++
	if b.state == StateHalfOpen {
		b.halfOpenRequests++
	}
}

// recordFailure records a failure
func (b *Breaker) recordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failureCount++
	b.totalFailures++
	b.lastFailureTime = time.Now()

	switch b.state {
	case StateClosed:
		if b.failureCount >= b.config.FailureThreshold {
			b.transitionToOpen()
		}
	case StateHalfOpen:
		b.transitionToOpen()
	}
}

// recordSuccess records a successful execution
func (b *Breaker) recordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failureCount = 0
	b.halfOpenRequests = 0

	if b.state == StateHalfOpen {
		b.transitionToClosed()
	}
}

// transitionToOpen transitions the circuit breaker to open state
func (b *Breaker) transitionToOpen() {
	if b.state != StateOpen {
		b.state = StateOpen
		b.stateChanges++
	}
}

// transitionToHalfOpen transitions the circuit breaker to half-open state
func (b *Breaker) transitionToHalfOpen() {
	if b.state != StateHalfOpen {
		b.state = StateHalfOpen
		b.halfOpenRequests = 0
		b.stateChanges++
	}
}

// transitionToClosed transitions the circuit breaker to closed state
func (b *Breaker) transitionToClosed() {
	if b.state != StateClosed {
		b.state = StateClosed
		b.failureCount = 0
		b.stateChanges++
	}
}

// GetState returns the current state
func (b *Breaker) GetState() State {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.state
}

// GetStateString returns the current state as a string
func (b *Breaker) GetStateString() string {
	return b.GetState().String()
}

// IsOpen returns true if the circuit breaker is open
func (b *Breaker) IsOpen() bool {
	return b.GetState() == StateOpen
}

// IsClosed returns true if the circuit breaker is closed
func (b *Breaker) IsClosed() bool {
	return b.GetState() == StateClosed
}

// IsHalfOpen returns true if the circuit breaker is half-open
func (b *Breaker) IsHalfOpen() bool {
	return b.GetState() == StateHalfOpen
}

// GetStats returns circuit breaker statistics
func (b *Breaker) GetStats() Stats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return Stats{
		State:            b.state.String(),
		FailureCount:     b.failureCount,
		TotalRequests:    b.totalRequests,
		TotalFailures:    b.totalFailures,
		TotalTimeouts:    b.totalTimeouts,
		StateChanges:     b.stateChanges,
		LastFailureTime:  b.lastFailureTime,
		HalfOpenRequests: b.halfOpenRequests,
	}
}

// Stats represents circuit breaker statistics
type Stats struct {
	State            string    `json:"state"`
	FailureCount     int       `json:"failure_count"`
	TotalRequests    int64     `json:"total_requests"`
	TotalFailures    int64     `json:"total_failures"`
	TotalTimeouts    int64     `json:"total_timeouts"`
	StateChanges     int64     `json:"state_changes"`
	LastFailureTime  time.Time `json:"last_failure_time"`
	HalfOpenRequests int       `json:"half_open_requests"`
}

// ForceOpen forces the circuit breaker to open state
func (b *Breaker) ForceOpen() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.transitionToOpen()
}

// ForceClose forces the circuit breaker to closed state
func (b *Breaker) ForceClose() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.transitionToClosed()
}

// Reset resets the circuit breaker to initial state
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.state = StateClosed
	b.failureCount = 0
	b.halfOpenRequests = 0
	b.lastFailureTime = time.Time{}
	b.totalRequests = 0
	b.totalFailures = 0
	b.totalTimeouts = 0
	b.stateChanges = 0
}
