package trace

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nxtrace/NTrace-core/trace/internal"
)

func TestMTRICMPRotatedListenerSurvivesProbeGenerationReset(t *testing.T) {
	conn, err := internal.ListenPacket("ip4:icmp", "127.0.0.1")
	if err != nil {
		t.Skipf("ICMP loopback socket unavailable: %v", err)
	}
	_ = conn.Close()

	workers := newMTRWorkerSession(t.Context())
	engine := newMTRICMPEngineState(Config{
		DstIP:    net.IPv4(127, 0, 0, 1),
		Timeout:  time.Second,
		ICMPMode: 1,
	}, 4, net.IPv4(127, 0, 0, 1))
	defer workers.shutdown(engine.close)
	if err := engine.startMTRSession(workers); err != nil {
		t.Fatalf("start ICMP listener: %v", err)
	}

	probeCtx, cancelProbe := context.WithCancel(workers.ctx)
	defer cancelProbe()
	result, err := engine.ProbeTTL(probeCtx, 1)
	if err != nil || !result.Success {
		t.Skipf("ICMP loopback replies unavailable: result=%+v, error=%v", result, err)
	}
	engine.seqCounter.Store(0xFFFF)
	result, err = engine.ProbeTTL(probeCtx, 1)
	if err != nil || !result.Success {
		t.Fatalf("probe after listener rotation = %+v, %v; want loopback reply", result, err)
	}

	cancelProbe()
	if err := engine.Reset(); err != nil {
		t.Fatalf("reset ICMP prober: %v", err)
	}
	// Continue probing while cancellation is processed; a single immediate reply
	// could race with the canceled listener closing its socket.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for deadline := time.Now().Add(100 * time.Millisecond); time.Now().Before(deadline); {
		<-ticker.C
		result, err = engine.ProbeTTL(workers.ctx, 1)
		if err != nil || !result.Success {
			t.Fatalf("probe after generation reset = %+v, %v; want loopback reply", result, err)
		}
	}
}

func TestMTRSchedulerResetCancelsProbeGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		var calls atomic.Int32
		firstStarted := make(chan struct{})
		firstCanceled := make(chan struct{})
		resetRequested := atomic.Bool{}
		prober := &mockTTLProber{
			probeFn: func(ctx context.Context, ttl int) (mtrProbeResult, error) {
				if calls.Add(1) == 1 {
					close(firstStarted)
					<-ctx.Done()
					close(firstCanceled)
					return mtrProbeResult{
						TTL:     ttl,
						Success: true,
						Addr:    &net.IPAddr{IP: net.ParseIP("192.0.2.1")},
						RTT:     time.Millisecond,
					}, nil
				}
				return mtrProbeResult{
					TTL:     ttl,
					Success: true,
					Addr:    &net.IPAddr{IP: net.ParseIP("192.0.2.2")},
					RTT:     time.Millisecond,
				}, nil
			},
		}

		agg := NewMTRAggregator()
		done := make(chan error, 1)
		go func() {
			done <- runMTRScheduler(ctx, prober, agg, mtrSchedulerConfig{
				BeginHop:         1,
				MaxHops:          1,
				HopInterval:      time.Second,
				MaxPerHop:        1,
				ParallelRequests: 1,
				IsResetRequested: func() bool { return resetRequested.Swap(false) },
			}, nil, nil)
		}()

		<-firstStarted
		resetRequested.Store(true)
		select {
		case <-firstCanceled:
		case <-time.After(20 * time.Millisecond):
			t.Fatal("reset did not cancel the previous probe generation")
		}

		if err := <-done; err != nil {
			t.Fatalf("runMTRScheduler returned error: %v", err)
		}
		stats := agg.Snapshot()
		if len(stats) != 1 || stats[0].IP != "192.0.2.2" || stats[0].Snt != 1 {
			t.Fatalf("post-reset stats = %+v, want only the new generation", stats)
		}
	})
}

func TestMTRSchedulerResetRetainsGlobalProbeCapacityUntilOldWorkerExits(t *testing.T) {
	var calls atomic.Int32
	resetRequested := atomic.Bool{}
	firstStarted := make(chan struct{})
	firstCanceled := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})

	prober := &mockTTLProber{
		probeFn: func(ctx context.Context, ttl int) (mtrProbeResult, error) {
			switch calls.Add(1) {
			case 1:
				close(firstStarted)
				<-ctx.Done()
				close(firstCanceled)
				<-releaseFirst
				return mtrProbeResult{TTL: ttl}, ctx.Err()
			case 2:
				close(secondStarted)
				return mtrProbeResult{TTL: ttl}, nil
			default:
				return mtrProbeResult{TTL: ttl}, nil
			}
		},
	}
	workers := newMTRWorkerSession(t.Context())
	defer workers.shutdown(func() { _ = prober.Close() })
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	defer release()

	rt, err := newMTRSchedulerRuntimeWithSession(workers, prober, NewMTRAggregator(), mtrSchedulerConfig{
		BeginHop:         1,
		MaxHops:          1,
		HopInterval:      time.Second,
		ParallelRequests: 1,
		IsResetRequested: func() bool { return resetRequested.Swap(false) },
	}, nil, nil)
	if err != nil {
		t.Fatalf("newMTRSchedulerRuntimeWithSession returned error: %v", err)
	}

	rt.launchProbe(1)
	<-firstStarted
	resetRequested.Store(true)
	rt.handleReset()
	select {
	case <-firstCanceled:
	case <-time.After(time.Second):
		t.Fatal("reset did not cancel the old probe")
	}
	if got := rt.inFlight; got != 1 {
		t.Fatalf("global in-flight probes after reset = %d, want 1 until the old worker exits", got)
	}

	release()
	var completed mtrCompletedProbe
	select {
	case completed = <-rt.resultCh:
	case <-time.After(time.Second):
		t.Fatal("old probe did not report completion accounting")
	}
	rt.processResult(completed)
	if got := rt.inFlight; got != 0 {
		t.Fatalf("global in-flight probes after old worker exit = %d, want 0", got)
	}

	rt.scheduleReady()
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("new generation probe did not start after capacity was released")
	}
	rt.processResult(<-rt.resultCh)
}

type closeBlockingTTLProber struct {
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newCloseBlockingTTLProber() *closeBlockingTTLProber {
	return &closeBlockingTTLProber{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (p *closeBlockingTTLProber) ProbeTTL(ctx context.Context, ttl int) (mtrProbeResult, error) {
	p.startOnce.Do(func() { close(p.started) })
	<-p.release
	return mtrProbeResult{TTL: ttl}, ctx.Err()
}

func (p *closeBlockingTTLProber) Reset() error { return nil }

func (p *closeBlockingTTLProber) Close() error {
	p.closeOnce.Do(func() { close(p.release) })
	return nil
}

func TestMTRSchedulerShutdownClosesProberBeforeWaitingWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		prober := newCloseBlockingTTLProber()
		done := make(chan error, 1)
		go func() {
			done <- runMTRScheduler(ctx, prober, NewMTRAggregator(), mtrSchedulerConfig{
				BeginHop:         1,
				MaxHops:          1,
				HopInterval:      time.Second,
				ParallelRequests: 1,
			}, nil, nil)
		}()

		<-prober.started
		cancel()
		select {
		case <-prober.release:
		case <-time.After(time.Millisecond):
			t.Error("scheduler waited for a worker before closing its prober")
			_ = prober.Close()
		}

		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("runMTRScheduler error = %v, want context.Canceled", err)
		}
	})
}

type listenerTrackingTTLProber struct {
	listenerStarted chan struct{}
	listenerDone    chan struct{}
	release         chan struct{}
	closeOnce       sync.Once
}

func newListenerTrackingTTLProber() *listenerTrackingTTLProber {
	return &listenerTrackingTTLProber{
		listenerStarted: make(chan struct{}),
		listenerDone:    make(chan struct{}),
		release:         make(chan struct{}),
	}
}

func (p *listenerTrackingTTLProber) startMTRSession(workers *mtrWorkerSession) error {
	workers.Go("mtr.test-listener", func() {
		close(p.listenerStarted)
		<-p.release
		close(p.listenerDone)
	})
	return nil
}

func (p *listenerTrackingTTLProber) ProbeTTL(_ context.Context, ttl int) (mtrProbeResult, error) {
	return mtrProbeResult{TTL: ttl}, nil
}

func (p *listenerTrackingTTLProber) Reset() error { return nil }

func (p *listenerTrackingTTLProber) Close() error {
	p.closeOnce.Do(func() { close(p.release) })
	return nil
}

func TestMTRSchedulerJoinsSessionListener(t *testing.T) {
	prober := newListenerTrackingTTLProber()
	err := runMTRScheduler(t.Context(), prober, NewMTRAggregator(), mtrSchedulerConfig{
		BeginHop:         1,
		MaxHops:          1,
		HopInterval:      time.Millisecond,
		MaxPerHop:        1,
		ParallelRequests: 1,
	}, nil, nil)
	if err != nil {
		t.Fatalf("runMTRScheduler returned error: %v", err)
	}

	select {
	case <-prober.listenerStarted:
	default:
		t.Fatal("session listener did not start")
	}
	select {
	case <-prober.listenerDone:
	default:
		t.Fatal("runMTRScheduler returned before the session listener stopped")
	}
	profile := goroutineProfileText(t)
	if strings.Contains(profile, `"owner":"mtr.test-listener"`) {
		t.Fatalf("session listener remained in the goroutine profile after shutdown:\n%s", profile)
	}
	if os.Getenv("MTR_GOROUTINE_LEAK_PROFILE") != "" && strings.Contains(profile, `"owner":"mtr.`) {
		t.Fatalf("MTR worker remained in the final goroutine profile:\n%s", profile)
	}
	writeRawGoroutineProfileFromEnv(t, "MTR_GOROUTINE_LEAK_PROFILE")
}

func TestMTRWorkerGoroutineProfileCarriesOwnerLabel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	prober := newCloseBlockingTTLProber()
	done := make(chan error, 1)
	go func() {
		done <- runMTRScheduler(ctx, prober, NewMTRAggregator(), mtrSchedulerConfig{
			BeginHop:         1,
			MaxHops:          1,
			HopInterval:      time.Second,
			ParallelRequests: 1,
		}, nil, nil)
	}()
	<-prober.started

	profile := goroutineProfileText(t)
	if !strings.Contains(profile, `"owner":"mtr.probe"`) {
		t.Fatalf("goroutine profile is missing the MTR owner label:\n%s", profile)
	}
	writeRawGoroutineProfileFromEnv(t, "MTR_GOROUTINE_ACTIVE_PROFILE")
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runMTRScheduler error = %v, want context.Canceled", err)
	}
}

func goroutineProfileText(t *testing.T) string {
	t.Helper()
	var profile bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&profile, 1); err != nil {
		t.Fatalf("write goroutine profile: %v", err)
	}
	return profile.String()
}

func writeRawGoroutineProfileFromEnv(t *testing.T, envName string) {
	t.Helper()
	path := os.Getenv(envName)
	if path == "" {
		return
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create goroutine profile: %v", err)
	}
	if err := pprof.Lookup("goroutine").WriteTo(file, 0); err != nil {
		_ = file.Close()
		t.Fatalf("write goroutine profile: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close goroutine profile: %v", err)
	}
}

type closeBlockingPreviewProber struct {
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newCloseBlockingPreviewProber() *closeBlockingPreviewProber {
	return &closeBlockingPreviewProber{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (p *closeBlockingPreviewProber) probeRound(ctx context.Context) (*Result, error) {
	p.startOnce.Do(func() { close(p.started) })
	<-p.release
	return nil, ctx.Err()
}

func (p *closeBlockingPreviewProber) peekPartialResult() *Result { return nil }

func (p *closeBlockingPreviewProber) close() {
	p.closeOnce.Do(func() { close(p.release) })
}

func TestMTRLoopShutdownClosesProberBeforeWaitingPreviewWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		prober := newCloseBlockingPreviewProber()
		done := make(chan error, 1)
		go func() {
			done <- mtrLoop(ctx, prober, Config{}, MTROptions{
				ProgressThrottle: time.Millisecond,
			}, NewMTRAggregator(), func(_ int, _ []MTRHopStat) {}, false, nil)
		}()

		<-prober.started
		cancel()
		select {
		case <-prober.release:
		case <-time.After(time.Millisecond):
			t.Error("MTR loop waited for the preview worker before closing its prober")
			prober.close()
		}

		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("mtrLoop error = %v, want context.Canceled", err)
		}
	})
}
