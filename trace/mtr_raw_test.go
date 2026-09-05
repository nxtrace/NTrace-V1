package trace

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/util"
)

func TestRunMTRRaw_EmitsPerAttemptRecords(t *testing.T) {
	old := mtrRawTracerouteFn
	t.Cleanup(func() { mtrRawTracerouteFn = old })

	mtrRawTracerouteFn = func(_ Method, cfg Config) (*Result, error) {
		res := &Result{
			Hops: make([][]Hop, 2),
			responses: map[int][]probeResponse{
				1: {{kind: probeResponseTransit, detail: "ICMP Time Exceeded"}},
				2: {{kind: probeResponseUnreachable, detail: "ICMP Host Unreachable", marker: "!H"}},
			},
		}
		res.Hops[0] = []Hop{{
			Success:  true,
			Address:  &net.IPAddr{IP: net.ParseIP("1.1.1.1")},
			Hostname: "one.one.one.one",
			TTL:      1,
			RTT:      15 * time.Millisecond,
			Geo: &ipgeo.IPGeoData{
				Asnumber: "13335",
				Country:  "美国",
				Prov:     "加州",
				City:     "洛杉矶",
				Owner:    "Cloudflare",
				Lat:      35.1234,
				Lng:      139.5678,
			},
			Lang: "cn",
		}}
		res.Hops[1] = []Hop{{
			Success: false,
			TTL:     2,
			Error:   errHopLimitTimeout,
		}}

		if cfg.RealtimePrinter != nil {
			cfg.RealtimePrinter(res.snapshotThroughTTL(1), 0)
			cfg.RealtimePrinter(res.snapshotThroughTTL(2), 1)
		}
		return res, nil
	}

	var records []MTRRawRecord
	err := RunMTRRaw(context.Background(), ICMPTrace, Config{Lang: "cn"}, MTRRawOptions{
		MaxRounds: 1,
		Interval:  time.Millisecond,
	}, func(rec MTRRawRecord) {
		records = append(records, rec)
	})
	if err != nil {
		t.Fatalf("RunMTRRaw returned error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if !records[0].Success || records[0].TTL != 1 || records[0].IP != "1.1.1.1" {
		t.Fatalf("unexpected first record: %+v", records[0])
	}
	if records[0].ASN != "13335" || records[0].Country == "" || records[0].Owner != "Cloudflare" {
		t.Fatalf("first record geo fields missing: %+v", records[0])
	}
	if records[1].Success || records[1].TTL != 2 {
		t.Fatalf("unexpected timeout record: %+v", records[1])
	}
	if records[0].Response == nil || records[0].Response.Kind != MTRResponseTransit {
		t.Fatalf("first record response = %#v, want transit", records[0].Response)
	}
	if records[1].Response == nil || records[1].Response.Kind != MTRResponseUnreachable || records[1].Response.Marker != "!H" {
		t.Fatalf("second record response = %#v, want unreachable !H", records[1].Response)
	}
}

func TestRunMTRRaw_RespectsMaxRoundsAndInterval(t *testing.T) {
	old := mtrRawTracerouteFn
	t.Cleanup(func() { mtrRawTracerouteFn = old })

	calls := 0
	mtrRawTracerouteFn = func(_ Method, _ Config) (*Result, error) {
		calls++
		return &Result{Hops: make([][]Hop, 0)}, nil
	}

	start := time.Now()
	err := RunMTRRaw(context.Background(), ICMPTrace, Config{}, MTRRawOptions{
		MaxRounds: 3,
		Interval:  20 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("RunMTRRaw returned error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("traceroute call count = %d, want 3", calls)
	}
	// Three rounds wait twice at 20ms each; allow a small scheduler tolerance below 40ms.
	if time.Since(start) < 38*time.Millisecond {
		t.Fatalf("interval appears not applied, elapsed=%v", time.Since(start))
	}
}

func TestRunMTRRaw_RoundBasedNaturalCompletionReportsDefaultMaxHops(t *testing.T) {
	var pathEnd *StopReason
	err := RunMTRRaw(context.Background(), ICMPTrace, Config{}, MTRRawOptions{
		MaxRounds: 1,
		RunRound: func(_ Method, _ Config) (*Result, error) {
			return &Result{Hops: make([][]Hop, 30)}, nil
		},
		OnPathEnd: func(reason *StopReason) {
			pathEnd = cloneStopReason(reason)
		},
	}, nil)
	if err != nil {
		t.Fatalf("RunMTRRaw returned error: %v", err)
	}
	if pathEnd == nil || pathEnd.Hop != 30 || pathEnd.Reason != StopReasonMaxHops {
		t.Fatalf("path end = %#v, want max_hops at default hop 30", pathEnd)
	}
}

func TestRunMTRRaw_ContextCancelStopsLoop(t *testing.T) {
	old := mtrRawTracerouteFn
	t.Cleanup(func() { mtrRawTracerouteFn = old })

	mtrRawTracerouteFn = func(_ Method, _ Config) (*Result, error) {
		time.Sleep(120 * time.Millisecond)
		return &Result{Hops: make([][]Hop, 0)}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := RunMTRRaw(ctx, ICMPTrace, Config{}, MTRRawOptions{
		MaxRounds: 10,
		Interval:  time.Second,
	}, nil)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Fatalf("RunMTRRaw should wait for in-flight round to finish before returning, elapsed=%v", elapsed)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("cancel took unexpectedly long, elapsed=%v", elapsed)
	}
}

func TestRunMTRRaw_RunRoundCancellationWaitsForCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		canceled := make(chan struct{})
		releaseCleanup := make(chan struct{})
		cleanupDone := make(chan struct{})
		done := make(chan struct{})
		var runErr error
		go func() {
			runErr = RunMTRRaw(ctx, ICMPTrace, Config{Context: context.Background()}, MTRRawOptions{
				RunRound: func(_ Method, cfg Config) (*Result, error) {
					defer close(cleanupDone)
					<-cfg.Context.Done()
					close(canceled)
					<-releaseCleanup
					return nil, cfg.Context.Err()
				},
			}, nil)
			close(done)
		}()
		synctest.Wait()

		cancel()
		synctest.Wait()
		select {
		case <-canceled:
		default:
			t.Error("RunRound did not observe cancellation through cfg.Context")
		}
		select {
		case <-done:
			t.Errorf("RunMTRRaw returned before RunRound cleanup: %v", runErr)
		default:
		}

		close(releaseCleanup)
		<-done
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("RunMTRRaw error = %v, want context.Canceled", runErr)
		}
		select {
		case <-cleanupDone:
		default:
			t.Fatal("RunMTRRaw returned without waiting for RunRound cleanup")
		}
	})
}

func TestRunMTRRaw_UsesRunRoundOverride(t *testing.T) {
	calls := 0
	err := RunMTRRaw(context.Background(), ICMPTrace, Config{}, MTRRawOptions{
		MaxRounds: 1,
		RunRound: func(_ Method, cfg Config) (*Result, error) {
			calls++
			if cfg.RealtimePrinter == nil {
				t.Fatal("expected RealtimePrinter to be populated for raw streaming")
			}
			return &Result{Hops: make([][]Hop, 0)}, nil
		},
	}, nil)
	if err != nil {
		t.Fatalf("RunMTRRaw returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("RunRound override called %d times, want 1", calls)
	}
}

func TestRunMTRRaw_RoundBasedNormalizesRuntimeConfig(t *testing.T) {
	oldSrcDev := util.SrcDev
	oldDisableMPLS := util.DisableMPLS
	t.Cleanup(func() {
		util.SrcDev = oldSrcDev
		util.DisableMPLS = oldDisableMPLS
	})

	util.SrcDev = "en0"
	util.DisableMPLS = true

	calls := 0
	err := RunMTRRaw(context.Background(), ICMPTrace, Config{}, MTRRawOptions{
		MaxRounds: 1,
		RunRound: func(_ Method, cfg Config) (*Result, error) {
			calls++
			if cfg.SourceDevice != "en0" {
				t.Fatalf("cfg.SourceDevice = %q, want en0", cfg.SourceDevice)
			}
			if cfg.DisableMPLS {
				t.Fatal("cfg.DisableMPLS = true, want false")
			}
			return &Result{Hops: make([][]Hop, 0)}, nil
		},
	}, nil)
	if err != nil {
		t.Fatalf("RunMTRRaw returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("RunRound override called %d times, want 1", calls)
	}
}
