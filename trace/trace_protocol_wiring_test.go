package trace

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

const traceWiringTestTTL = 1

type protocolSettlementWiringTest struct {
	name   string
	res    *Result
	final  *atomic.Int32
	launch func()
	wait   func()
	send   func(context.Context) error
	setSem func(*semaphore.Weighted)
}

type semaphoreArrivalContext struct {
	context.Context
	arrived chan struct{}
	once    sync.Once
}

func (c *semaphoreArrivalContext) Err() error {
	c.once.Do(func() { close(c.arrived) })
	return c.Context.Err()
}

type retryRegistrationContext struct {
	context.Context
	armed      atomic.Bool
	registered atomic.Bool
	register   func()
}

func (c *retryRegistrationContext) Done() <-chan struct{} {
	if c.armed.Load() && c.registered.CompareAndSwap(false, true) {
		c.register()
	}
	return c.Context.Done()
}

func (c *retryRegistrationContext) Err() error {
	c.armed.Store(true)
	return c.Context.Err()
}

func prepareProtocolSettlementWiringTest(t *testing.T, test protocolSettlementWiringTest, settleBeforeLaunchDone bool) {
	t.Helper()
	test.res.Hops = [][]Hop{{{Success: true, TTL: traceWiringTestTTL}}}
	test.res.tailDone = []bool{true}
	test.res.responses = map[int][]probeResponse{
		traceWiringTestTTL: {{kind: probeResponseUnreachable}},
	}
	test.res.attempts = nil
	test.final.Store(-1)
	if !test.res.markAttemptLaunched(traceWiringTestTTL, 0, test.final) {
		t.Fatal("test attempt was not launched")
	}
	if settleBeforeLaunchDone {
		test.res.settleAttempt(traceWiringTestTTL, 0)
		return
	}
	test.res.markTTLLaunchDone(traceWiringTestTTL)
}

func prepareProtocolSecondTTLCheckWiringTest(t *testing.T, test protocolSettlementWiringTest) {
	t.Helper()
	test.res.Hops = [][]Hop{nil}
	test.res.tailDone = []bool{false}
	test.res.responses = map[int][]probeResponse{
		traceWiringTestTTL: {{kind: probeResponseUnreachable}},
	}
	test.res.attempts = nil
	test.final.Store(-1)
	if !test.res.markAttemptLaunched(traceWiringTestTTL, 0, test.final) {
		t.Fatal("test attempt was not launched")
	}
	test.res.markTTLLaunchDone(traceWiringTestTTL)
}

func waitForProtocolWiringSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func makeProtocolWiringHopVisible(res *Result) {
	res.lock.Lock()
	defer res.lock.Unlock()
	res.Hops[0] = []Hop{{Success: true, TTL: traceWiringTestTTL}}
}

func testProtocolSecondTTLCheckWiring(t *testing.T, test protocolSettlementWiringTest) {
	t.Helper()
	prepareProtocolSecondTTLCheckWiringTest(t, test)

	sem := semaphore.NewWeighted(1)
	if err := sem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("pre-acquire semaphore: %v", err)
	}
	test.setSem(sem)

	baseCtx, cancel := context.WithCancel(context.Background())
	ctx := &semaphoreArrivalContext{Context: baseCtx, arrived: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { sem.Release(1) }) }
	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- test.send(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		makeProtocolWiringHopVisible(test.res)
		cancel()
		release()
		waitForProtocolWiringSignal(t, done, "send cleanup")
	})

	waitForProtocolWiringSignal(t, ctx.arrived, "semaphore acquire")
	makeProtocolWiringHopVisible(test.res)
	release()
	waitForProtocolWiringSignal(t, done, "send completion")
	if err := <-errCh; err != nil {
		t.Fatalf("send() error = %v", err)
	}
	if got := test.final.Load(); got != traceWiringTestTTL {
		t.Fatalf("final = %d, want %d", got, traceWiringTestTTL)
	}
}

func TestProtocolStableUnreachableSettlementWiring(t *testing.T) {
	config := Config{NumMeasurements: 1, MaxAttempts: 1}
	icmp4 := &ICMPTracer{Config: config}
	icmp6 := &ICMPTracerv6{Config: config}
	tcp4 := &TCPTracer{Config: config}
	tcp6 := &TCPTracerIPv6{Config: config}
	udp4 := &UDPTracer{Config: config}
	udp6 := &UDPTracerIPv6{Config: config}

	tests := []protocolSettlementWiringTest{
		{name: "icmp4", res: &icmp4.res, final: &icmp4.final, launch: func() { icmp4.launchTTL(context.Background(), nil, traceWiringTestTTL) }, wait: icmp4.wg.Wait, send: func(ctx context.Context) error { return icmp4.send(ctx, nil, traceWiringTestTTL, 0) }, setSem: func(sem *semaphore.Weighted) { icmp4.sem = sem }},
		{name: "icmp6", res: &icmp6.res, final: &icmp6.final, launch: func() { icmp6.launchTTL(context.Background(), nil, traceWiringTestTTL) }, wait: icmp6.wg.Wait, send: func(ctx context.Context) error { return icmp6.send(ctx, nil, traceWiringTestTTL, 0) }, setSem: func(sem *semaphore.Weighted) { icmp6.sem = sem }},
		{name: "tcp4", res: &tcp4.res, final: &tcp4.final, launch: func() { tcp4.launchTTL(context.Background(), nil, traceWiringTestTTL) }, wait: tcp4.wg.Wait, send: func(ctx context.Context) error { return tcp4.send(ctx, nil, traceWiringTestTTL, 0) }, setSem: func(sem *semaphore.Weighted) { tcp4.sem = sem }},
		{name: "tcp6", res: &tcp6.res, final: &tcp6.final, launch: func() { tcp6.launchTTL(context.Background(), nil, traceWiringTestTTL) }, wait: tcp6.wg.Wait, send: func(ctx context.Context) error { return tcp6.send(ctx, nil, traceWiringTestTTL, 0) }, setSem: func(sem *semaphore.Weighted) { tcp6.sem = sem }},
		{name: "udp4", res: &udp4.res, final: &udp4.final, launch: func() { udp4.launchTTL(context.Background(), nil, traceWiringTestTTL) }, wait: udp4.wg.Wait, send: func(ctx context.Context) error { return udp4.send(ctx, nil, traceWiringTestTTL, 0) }, setSem: func(sem *semaphore.Weighted) { udp4.sem = sem }},
		{name: "udp6", res: &udp6.res, final: &udp6.final, launch: func() { udp6.launchTTL(context.Background(), nil, traceWiringTestTTL) }, wait: udp6.wg.Wait, send: func(ctx context.Context) error { return udp6.send(ctx, nil, traceWiringTestTTL, 0) }, setSem: func(sem *semaphore.Weighted) { udp6.sem = sem }},
	}

	for _, test := range tests {
		t.Run(test.name+"/launch_done", func(t *testing.T) {
			prepareProtocolSettlementWiringTest(t, test, true)
			test.launch()
			test.wait()
			if got := test.final.Load(); got != traceWiringTestTTL {
				t.Fatalf("final = %d, want %d", got, traceWiringTestTTL)
			}
		})

		t.Run(test.name+"/skipped_send", func(t *testing.T) {
			prepareProtocolSettlementWiringTest(t, test, false)
			if err := test.send(context.Background()); err != nil {
				t.Fatalf("send() error = %v", err)
			}
			if got := test.final.Load(); got != traceWiringTestTTL {
				t.Fatalf("final = %d, want %d", got, traceWiringTestTTL)
			}
		})

		t.Run(test.name+"/second_ttl_check", func(t *testing.T) {
			testProtocolSecondTTLCheckWiring(t, test)
		})
	}
}

func closedMatchTaskQueue(task matchTask) chan matchTask {
	queue := make(chan matchTask, 1)
	queue <- task
	close(queue)
	return queue
}

func TestProtocolMatchWorkerRetryWiring(t *testing.T) {
	const (
		seq16   = traceWiringTestTTL << 8
		seq32   = traceWiringTestTTL << 24
		srcPort = 33434
	)
	start := time.Unix(100, 0)
	finish := start.Add(time.Millisecond)
	icmpTask := matchTask{seq: seq16, finish: finish}
	portTask16 := matchTask{seq: seq16, srcPort: srcPort, finish: finish}
	portTask32 := matchTask{seq: seq32, srcPort: srcPort, finish: finish}

	icmp4 := &ICMPTracer{sentAt: make(map[int]time.Time), matchQ: closedMatchTaskQueue(icmpTask)}
	icmp6 := &ICMPTracerv6{sentAt: make(map[int]time.Time), matchQ: closedMatchTaskQueue(icmpTask)}
	tcp4 := &TCPTracer{sentAt: make(map[int]sentInfo), matchQ: closedMatchTaskQueue(portTask32)}
	tcp6 := &TCPTracerIPv6{sentAt: make(map[int]sentInfo), matchQ: closedMatchTaskQueue(portTask32)}
	udp4 := &UDPTracer{sentAt: make(map[int]sentInfo), matchQ: closedMatchTaskQueue(portTask16)}
	udp6 := &UDPTracerIPv6{sentAt: make(map[int]sentInfo), matchQ: closedMatchTaskQueue(portTask16)}

	tests := []struct {
		name        string
		register    func()
		startWorker func(context.Context)
		wait        func()
		sentRemoved func() bool
	}{
		{name: "icmp4", register: func() { icmp4.storeSent(seq16, start) }, startWorker: func(ctx context.Context) { icmp4.wg.Add(1); go icmp4.matchWorker(ctx) }, wait: icmp4.wg.Wait, sentRemoved: func() bool { _, ok := icmp4.lookupSent(seq16); return !ok }},
		{name: "icmp6", register: func() { icmp6.storeSent(seq16, start) }, startWorker: func(ctx context.Context) { icmp6.wg.Add(1); go icmp6.matchWorker(ctx) }, wait: icmp6.wg.Wait, sentRemoved: func() bool { _, ok := icmp6.lookupSent(seq16); return !ok }},
		{name: "tcp4", register: func() { tcp4.storeSent(seq32, srcPort, 0, start) }, startWorker: func(ctx context.Context) { tcp4.wg.Add(1); go tcp4.matchWorker(ctx) }, wait: tcp4.wg.Wait, sentRemoved: func() bool { _, _, ok := tcp4.lookupSent(seq32); return !ok }},
		{name: "tcp6", register: func() { tcp6.storeSent(seq32, srcPort, 0, start) }, startWorker: func(ctx context.Context) { tcp6.wg.Add(1); go tcp6.matchWorker(ctx) }, wait: tcp6.wg.Wait, sentRemoved: func() bool { _, _, ok := tcp6.lookupSent(seq32); return !ok }},
		{name: "udp4", register: func() { udp4.storeSent(seq16, traceWiringTestTTL, 0, srcPort, start) }, startWorker: func(ctx context.Context) { udp4.wg.Add(1); go udp4.matchWorker(ctx) }, wait: udp4.wg.Wait, sentRemoved: func() bool { _, _, _, _, ok := udp4.lookupSent(seq16); return !ok }},
		{name: "udp6", register: func() { udp6.storeSent(seq16, srcPort, start) }, startWorker: func(ctx context.Context) { udp6.wg.Add(1); go udp6.matchWorker(ctx) }, wait: udp6.wg.Wait, sentRemoved: func() bool { _, _, ok := udp6.lookupSent(seq16); return !ok }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &retryRegistrationContext{Context: context.Background(), register: test.register}
			test.startWorker(ctx)
			test.wait()
			if !ctx.registered.Load() {
				t.Fatal("match worker did not reach the retry wait after the initial lookup miss")
			}
			if !test.sentRemoved() {
				t.Fatal("match worker did not consume the probe registered during the retry wait")
			}
		})
	}
}
