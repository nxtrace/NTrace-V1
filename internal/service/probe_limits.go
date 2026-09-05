package service

import (
	"fmt"

	"github.com/nxtrace/NTrace-core/trace"
	"github.com/nxtrace/NTrace-core/util"
)

const (
	MaxProbeHops     = 255
	MaxProbeQueries  = 63
	MaxProbeParallel = 256
	MaxProbeAttempts = 63
)

// ValidateProbeLimits bounds deploy/MCP allocations before target resolution or
// runtime initialization. Callers executing MTR must supply its effective
// Queries/MaxAttempts (both 1), not the ignored request values.
func ValidateProbeLimits(cfg trace.Config) error {
	maxHops := positiveOrDefault(cfg.MaxHops, defaultMaxHops)
	beginHop := positiveOrDefault(cfg.BeginHop, defaultBeginHop)
	queries := positiveOrDefault(cfg.NumMeasurements, defaultQueries)
	parallel := positiveOrDefault(cfg.ParallelRequests, defaultParallelRequests)
	for _, limit := range []struct {
		name       string
		value, max int
	}{
		{"max_hops", maxHops, MaxProbeHops},
		{"begin_hop", beginHop, maxHops},
		{"queries", queries, MaxProbeQueries},
		{"parallel_requests", parallel, MaxProbeParallel},
	} {
		if limit.value > limit.max {
			return fmt.Errorf("%s must be within range 1-%d", limit.name, limit.max)
		}
	}
	attempts := cfg.MaxAttempts
	if attempts <= 0 {
		attempts = util.EnvMaxAttempts
	}
	// trace.deriveMaxAttempts retains values >= queries; its automatic defaults
	// are at most max(queries, 10), already bounded by the queries check above.
	if attempts > MaxProbeAttempts {
		return fmt.Errorf("max_attempts must be within range 1-%d", MaxProbeAttempts)
	}
	return nil
}

func validateTraceRequestLimits(req TraceRequest) error {
	return ValidateProbeLimits(trace.Config{
		MaxHops: req.MaxHops, BeginHop: req.BeginHop,
		NumMeasurements: req.Queries, ParallelRequests: req.ParallelRequests,
		MaxAttempts: req.MaxAttempts,
	})
}
