package service

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
	mtutrace "github.com/nxtrace/NTrace-core/trace/mtu"
	"github.com/nxtrace/NTrace-core/util"
)

func TestProbeLimitsBoundaries(t *testing.T) {
	oldEnv := util.EnvMaxAttempts
	t.Cleanup(func() { util.EnvMaxAttempts = oldEnv })
	maxInt := int(^uint(0) >> 1)
	for _, tc := range []struct {
		name  string
		cfg   trace.Config
		env   int
		field string
	}{
		{"defaults", trace.Config{}, 0, ""},
		{"negative_defaults", trace.Config{MaxHops: -1, BeginHop: -1, NumMeasurements: -1, ParallelRequests: -1, MaxAttempts: -1}, -1, ""},
		{"boundaries", trace.Config{MaxHops: 255, BeginHop: 255, NumMeasurements: 63, ParallelRequests: 256, MaxAttempts: 63}, 0, ""},
		{"default_attempts", trace.Config{NumMeasurements: 63}, 0, ""},
		{"small_attempts_derived", trace.Config{NumMeasurements: 63, MaxAttempts: 1}, 1000, ""},
		{"hops", trace.Config{MaxHops: 256}, 0, "max_hops"},
		{"huge_hops", trace.Config{MaxHops: maxInt}, 0, "max_hops"},
		{"begin", trace.Config{BeginHop: 31}, 0, "begin_hop"},
		{"huge_begin", trace.Config{BeginHop: maxInt}, 0, "begin_hop"},
		{"queries", trace.Config{NumMeasurements: 64}, 0, "queries"},
		{"huge_queries", trace.Config{NumMeasurements: maxInt}, 0, "queries"},
		{"parallel", trace.Config{ParallelRequests: 257}, 0, "parallel_requests"},
		{"huge_parallel", trace.Config{ParallelRequests: maxInt}, 0, "parallel_requests"},
		{"attempts", trace.Config{MaxAttempts: 64}, 0, "max_attempts"},
		{"huge_attempts", trace.Config{MaxAttempts: maxInt}, 0, "max_attempts"},
		{"env_boundary", trace.Config{}, 63, ""},
		{"env_excessive", trace.Config{}, 64, "max_attempts"},
		{"negative_inherits_env", trace.Config{MaxAttempts: -1}, maxInt, "max_attempts"},
		{"explicit_overrides_env", trace.Config{MaxAttempts: 63}, maxInt, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			util.EnvMaxAttempts = tc.env
			err := ValidateProbeLimits(tc.cfg)
			if tc.field == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.field+" must be within range 1-") {
				t.Fatalf("error=%v, want %s range error", err, tc.field)
			}
		})
	}
}

func TestServiceProbeLimitsBeforeRuntime(t *testing.T) {
	t.Chdir(t.TempDir())
	oldLookup := traceTargetLookupFn
	t.Cleanup(func() { traceTargetLookupFn = oldLookup })
	traceTargetLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		t.Error("invalid request reached DNS")
		return nil, errors.New("unexpected lookup")
	}
	svc := New()
	for _, tc := range []struct {
		name, field string
		run         func() error
	}{
		{"trace", "queries", func() error {
			_, err := svc.Traceroute(context.Background(), TraceRequest{Target: "example.invalid", DataProvider: "DN42", Queries: 64})
			return err
		}},
		{"report", "parallel_requests", func() error {
			_, err := svc.MTRReport(context.Background(), MTRReportRequest{TraceRequest: TraceRequest{Target: "example.invalid", DataProvider: "DN42", ParallelRequests: 257}})
			return err
		}},
		{"raw", "max_hops", func() error {
			_, err := svc.MTRRaw(context.Background(), MTRRawRequest{TraceRequest: TraceRequest{Target: "example.invalid", DataProvider: "DN42", MaxHops: 256}})
			return err
		}},
		{"mtu_hops", "max_hops", func() error {
			_, err := svc.MTUTrace(context.Background(), MTUTraceRequest{Target: "example.invalid", DataProvider: "DN42", MaxHops: 256})
			return err
		}},
		{"mtu_queries", "queries", func() error {
			_, err := svc.MTUTrace(context.Background(), MTUTraceRequest{Target: "example.invalid", DataProvider: "DN42", Queries: 64})
			return err
		}},
		{"mtu_begin", "begin_hop", func() error {
			_, err := svc.MTUTrace(context.Background(), MTUTraceRequest{Target: "example.invalid", DataProvider: "DN42", BeginHop: 31})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RuntimeMu.Lock()
			done := make(chan error, 1)
			go func() { done <- tc.run() }()
			select {
			case err := <-done:
				RuntimeMu.Unlock()
				if err == nil || !strings.Contains(err.Error(), tc.field) {
					t.Fatalf("error=%v", err)
				}
			case <-time.After(time.Second):
				RuntimeMu.Unlock()
				<-done
				t.Fatal("invalid request waited for runtime lock")
			}
			if _, err := os.Stat("nt_config.yaml"); !os.IsNotExist(err) {
				t.Fatalf("DN42 initialization ran: %v", err)
			}
		})
	}
}

func TestServiceProbeLimitsLegitimateControls(t *testing.T) {
	defer stubServiceRuntimeForTests(t)()
	oldEnv, oldLookup := util.EnvMaxAttempts, traceTargetLookupFn
	t.Cleanup(func() { util.EnvMaxAttempts, traceTargetLookupFn = oldEnv, oldLookup })
	util.EnvMaxAttempts = 64
	traceTargetLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("192.0.2.1"), nil
	}
	traces, reports, raws, mtus := 0, 0, 0, 0
	tracerouteWithContextFn = func(_ context.Context, _ trace.Method, cfg trace.Config) (*trace.Result, error) {
		traces++
		if cfg.MaxHops != 255 || cfg.BeginHop != 255 || cfg.NumMeasurements != 63 || cfg.ParallelRequests != 256 || cfg.MaxAttempts != 63 {
			t.Errorf("unexpected trace config: %+v", cfg)
		}
		return &trace.Result{}, nil
	}
	runMTRFn = func(_ context.Context, _ trace.Method, cfg trace.Config, opts trace.MTROptions, _ trace.MTROnSnapshot) error {
		reports++
		if cfg.NumMeasurements != 1 || cfg.MaxAttempts != 1 || opts.MaxPerHop != 10 {
			t.Error("MTR effective/default parameters changed")
		}
		return nil
	}
	runMTRRawFn = func(_ context.Context, _ trace.Method, cfg trace.Config, opts trace.MTRRawOptions, _ trace.MTRRawOnRecord) error {
		raws++
		if cfg.NumMeasurements != 1 || cfg.MaxAttempts != 1 || opts.MaxPerHop != 3 {
			t.Error("raw effective/default parameters changed")
		}
		return nil
	}
	runMTUTraceFn = func(_ context.Context, cfg mtutrace.Config) (*mtutrace.Result, error) {
		mtus++
		if cfg.MaxHops != 255 || cfg.BeginHop != 255 || cfg.Queries != 63 {
			t.Error("MTU limits changed valid input")
		}
		return &mtutrace.Result{}, nil
	}
	svc := New()
	base := TraceRequest{Target: "example.invalid", DataProvider: "disable-geoip", MaxHops: 255, BeginHop: 255, Queries: 63, ParallelRequests: 256, MaxAttempts: 63}
	if _, err := svc.Traceroute(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	base.Queries, base.MaxAttempts = int(^uint(0)>>1), int(^uint(0)>>1)
	if _, err := svc.MTRReport(context.Background(), MTRReportRequest{TraceRequest: base}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MTRRaw(context.Background(), MTRRawRequest{TraceRequest: base}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.MTUTrace(context.Background(), MTUTraceRequest{Target: "example.invalid", SourceAddress: "192.0.2.2", DataProvider: "disable-geoip", MaxHops: 255, BeginHop: 255, Queries: 63}); err != nil {
		t.Fatal(err)
	}
	if traces != 1 || reports != 1 || raws != 1 || mtus != 1 {
		t.Fatalf("calls=%d,%d,%d,%d", traces, reports, raws, mtus)
	}
}
