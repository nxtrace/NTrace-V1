package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/trace/internal"
)

// Pause SendICMP after sendProbe has loaded its socket, before the first socket
// operation. Cancellation on release avoids sending a packet in these tests.
type mtrSendGateContext struct {
	context.Context
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *mtrSendGateContext) Done() <-chan struct{} {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.Context.Done()
}

func newMTRSendGate(t *testing.T) (*mtrSendGateContext, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	gate := &mtrSendGateContext{Context: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	finish := func() {
		once.Do(func() { cancel(); close(gate.release) })
	}
	t.Cleanup(finish)
	return gate, finish
}

func newMTRSendGateEngine(tos int) *mtrICMPEngine {
	engine := newMTRICMPEngineState(Config{DstIP: net.IPv4(127, 0, 0, 1), TOS: tos}, 4, net.IP{1, 2, 3})
	// No real socket is required: the gated send is canceled before accessing it.
	// The deliberately invalid source makes a later rotation fail during setup.
	engine.spec.Store(&internal.ICMPSpec{IPVersion: 4})
	engine.sentAt = make(map[int]mtrProbeMeta)
	engine.replied = make(map[int]*mtrProbeReply)
	engine.probeNotify = make(map[int]chan struct{})
	return engine
}

func waitMTRTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(description)
	}
}

func TestMTRICMPRotationWaitsForActualSend(t *testing.T) {
	for _, tos := range []int{0, 184} {
		t.Run(fmt.Sprint(tos), func(t *testing.T) {
			engine := newMTRSendGateEngine(tos)
			engine.seqCounter.Store(0xfffe)
			oldSpec := engine.spec.Load()
			rotationStarted := make(chan struct{})
			engine.listenerCancel = func() { close(rotationStarted) }
			gate, finish := newMTRSendGate(t)
			first := make(chan error, 1)
			go func() { _, err := engine.ProbeTTL(gate, 1); first <- err }()
			waitMTRTestSignal(t, gate.entered, "first probe did not reach its socket send")

			second := make(chan error, 1)
			secondStarted := make(chan struct{})
			go func() {
				close(secondStarted)
				_, err := engine.ProbeTTL(t.Context(), 2)
				second <- err
			}()
			waitMTRTestSignal(t, secondStarted, "second probe did not start")
			select {
			case <-rotationStarted:
				t.Error("sequence wrap closed a socket while another probe was sending")
			case <-time.After(50 * time.Millisecond):
			}
			if engine.spec.Load() != oldSpec {
				t.Error("active socket changed before the preceding send completed")
			}
			finish()
			select {
			case err := <-first:
				if !errors.Is(err, context.Canceled) || IsInitializationError(err) {
					t.Fatalf("send cancellation became a backend failure: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("first probe deadlocked after cancellation")
			}
			select {
			case err := <-second:
				if !IsInitializationError(err) {
					t.Fatalf("real rotation setup failure was hidden: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("rotation deadlocked after the prior send finished")
			}
		})
	}
}

func TestMTRICMPCloseAndResetCanInterruptSending(t *testing.T) {
	for _, action := range []string{"close", "reset"} {
		t.Run(action, func(t *testing.T) {
			engine := newMTRSendGateEngine(184)
			gate, finish := newMTRSendGate(t)
			probe := make(chan error, 1)
			go func() { _, err := engine.ProbeTTL(gate, 1); probe <- err }()
			waitMTRTestSignal(t, gate.entered, "probe did not reach its socket send")
			stopped := make(chan struct{})
			go func() {
				if action == "close" {
					engine.close()
				} else {
					_ = engine.Reset()
				}
				close(stopped)
			}()
			waitMTRTestSignal(t, stopped, "lifecycle action blocked behind the socket send")
			finish()
			select {
			case err := <-probe:
				if !errors.Is(err, context.Canceled) || IsInitializationError(err) {
					t.Fatalf("lifecycle cancellation became a backend failure: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("probe deadlocked after lifecycle cancellation")
			}
		})
	}
}

// Each SendICMP asks for Done once; the next call occurs in ProbeTTL's reply
// select. Detect that boundary without an injected sender or timing assumptions.
type mtrReplyWaitContext struct {
	context.Context
	calls   atomic.Int32
	waiting chan struct{}
}

func (c *mtrReplyWaitContext) Done() <-chan struct{} {
	if c.calls.Add(1) == 2 {
		close(c.waiting)
	}
	return c.Context.Done()
}

func TestMTRICMPDoesNotSerializeReplyWaiting(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1)
	spec := internal.NewICMPSpec(4, 1, 123, ip, ip)
	if err := spec.InitICMP(); err != nil {
		t.Skipf("ICMP loopback socket unavailable: %v", err)
	}
	defer spec.Close()
	engine := newMTRSendGateEngine(0)
	engine.srcIP = ip
	engine.config.Timeout = 5 * time.Second
	engine.spec.Store(spec)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	results := make(chan error, 2)
	for ttl := 1; ttl <= 2; ttl++ {
		probeCtx := &mtrReplyWaitContext{Context: ctx, waiting: make(chan struct{})}
		go func() { _, err := engine.ProbeTTL(probeCtx, ttl); results <- err }()
		waitMTRTestSignal(t, probeCtx.waiting, "another probe's reply wait blocked sending")
	}
	cancel()
	for range 2 {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("waiting probe failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("reply waiter deadlocked after cancellation")
		}
	}
}
