package wshandle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"
)

var errSupervisorTestWireClosed = errors.New("supervisor test wire closed")

type supervisorTestDialResult struct {
	wire wsWire
	err  error
}

type supervisorTestDialer struct {
	calls   chan wsDialRequest
	results chan supervisorTestDialResult
}

func newSupervisorTestDialer() *supervisorTestDialer {
	return &supervisorTestDialer{
		calls:   make(chan wsDialRequest, 16),
		results: make(chan supervisorTestDialResult, 16),
	}
}

func (d *supervisorTestDialer) dial(ctx context.Context, req wsDialRequest) (wsWire, *websocket.Conn, error) {
	select {
	case d.calls <- req:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	select {
	case result := <-d.results:
		return result.wire, nil, result.err
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

type supervisorTestRead struct {
	data string
	err  error
}

type supervisorTestWrite struct {
	messageType int
	data        string
}

type supervisorTestWire struct {
	reads      chan supervisorTestRead
	writes     chan supervisorTestWrite
	closed     chan struct{}
	closeOnce  sync.Once
	writeGate  <-chan struct{}
	writeError error
}

func newSupervisorTestWire() *supervisorTestWire {
	return &supervisorTestWire{
		reads:  make(chan supervisorTestRead, wsClientReceiveBacklog+128),
		writes: make(chan supervisorTestWrite, 32),
		closed: make(chan struct{}),
	}
}

func (w *supervisorTestWire) ReadMessage() (int, []byte, error) {
	select {
	case <-w.closed:
		return 0, nil, errSupervisorTestWireClosed
	default:
	}

	select {
	case event := <-w.reads:
		return websocket.TextMessage, []byte(event.data), event.err
	case <-w.closed:
		return 0, nil, errSupervisorTestWireClosed
	}
}

func (w *supervisorTestWire) SetWriteDeadline(time.Time) error {
	return nil
}

func (w *supervisorTestWire) WriteMessage(messageType int, data []byte) error {
	write := supervisorTestWrite{messageType: messageType, data: string(append([]byte(nil), data...))}
	select {
	case w.writes <- write:
	case <-w.closed:
		return errSupervisorTestWireClosed
	}

	if w.writeGate != nil {
		select {
		case <-w.writeGate:
		case <-w.closed:
			return errSupervisorTestWireClosed
		}
	}
	return w.writeError
}

func (w *supervisorTestWire) Close() error {
	w.closeOnce.Do(func() {
		close(w.closed)
	})
	return nil
}

func (w *supervisorTestWire) isClosed() bool {
	select {
	case <-w.closed:
		return true
	default:
		return false
	}
}

func installSupervisorTestDialer(dialer *supervisorTestDialer) func() {
	oldDialFn := wsDialFn
	oldEnvToken := envToken
	wsDialFn = dialer.dial
	envToken = "supervisor-test-token"
	return func() {
		wsDialFn = oldDialFn
		envToken = oldEnvToken
	}
}

func newSupervisorTestConn(ctx context.Context) *WsConn {
	return newManagedWsConn(ctx, make(chan os.Signal, 1), wsEndpoint{
		host:   "api.nxtrace.org",
		port:   "443",
		fastIP: "192.0.2.1",
		direct: true,
	})
}

func supervisorDialCallCount(dialer *supervisorTestDialer) int {
	count := 0
	for {
		select {
		case <-dialer.calls:
			count++
		default:
			return count
		}
	}
}

func requireSupervisorWrite(t *testing.T, wire *supervisorTestWire, wantType int, wantData string) {
	t.Helper()
	select {
	case got := <-wire.writes:
		if got.messageType != wantType || got.data != wantData {
			t.Fatalf("write = (%d, %q), want (%d, %q)", got.messageType, got.data, wantType, wantData)
		}
	default:
		t.Fatalf("missing write (%d, %q)", wantType, wantData)
	}
}

func requireNoSupervisorWrite(t *testing.T, wire *supervisorTestWire) {
	t.Helper()
	select {
	case got := <-wire.writes:
		t.Fatalf("unexpected write = (%d, %q)", got.messageType, got.data)
	default:
	}
}

func requireSupervisorReceive(t *testing.T, conn *WsConn, want string) {
	t.Helper()
	select {
	case got := <-conn.MsgReceiveCh:
		if got != want {
			t.Fatalf("receive = %q, want %q", got, want)
		}
	default:
		t.Fatalf("missing receive message %q", want)
	}
}

func requireNoSupervisorReceive(t *testing.T, conn *WsConn) {
	t.Helper()
	select {
	case got := <-conn.MsgReceiveCh:
		t.Fatalf("unexpected receive message %q", got)
	default:
	}
}

func TestManagedSupervisorRetriesDialWithVirtualTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{err: errors.New("dial failed")}
		dialer.results <- supervisorTestDialResult{err: errors.New("retry dial failed")}
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()

		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("initial dial calls = %d, want 1", got)
		}
		if conn.IsConnected() || conn.IsConnecting() {
			t.Fatal("failed dial should enter retry wait")
		}

		time.Sleep(wsClientReconnectDelay - time.Nanosecond)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 0 {
			t.Fatalf("early initial retry calls = %d, want 0", got)
		}

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("initial retry dial calls = %d, want 1", got)
		}
		if conn.IsConnected() || conn.IsConnecting() {
			t.Fatal("failed reconnect should enter retry wait")
		}

		time.Sleep(wsClientDialRetryDelay - time.Nanosecond)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 0 {
			t.Fatalf("early subsequent retry calls = %d, want 0", got)
		}

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("subsequent retry dial calls = %d, want 1", got)
		}
		if !conn.IsConnected() {
			t.Fatal("successful retry should publish connected state")
		}
	})
}

func TestSyncFirstCredentialFailureReusesPreservedCacheOnRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		oldDialFn := wsDialFn
		oldTokenFn := wsGetTokenFn
		oldEnvToken := envToken
		oldCacheToken := loadCachedToken()
		defer func() {
			wsDialFn = oldDialFn
			wsGetTokenFn = oldTokenFn
			envToken = oldEnvToken
			storeCachedToken(oldCacheToken)
		}()

		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		wsDialFn = dialer.dial
		envToken = ""
		storeCachedToken("preserved-token")
		var tokenCalls atomic.Int32
		wsGetTokenFn = func(context.Context, string, string, string) (string, error) {
			tokenCalls.Add(1)
			return "", errors.New("fresh token failed")
		}

		conn := newManagedWsConnWithPolicy(
			context.Background(),
			make(chan os.Signal, 1),
			wsEndpoint{host: "api.nxtrace.org", port: "443", fastIP: "192.0.2.1", direct: true},
			true,
		)
		defer conn.Close()
		synctest.Wait()
		if got := tokenCalls.Load(); got != 1 {
			t.Fatalf("fresh token calls = %d, want 1", got)
		}
		if got := loadCachedToken(); got != "preserved-token" {
			t.Fatalf("cached token = %q, want preserved token", got)
		}
		if got := supervisorDialCallCount(dialer); got != 0 {
			t.Fatalf("dial calls before credential retry = %d, want 0", got)
		}

		time.Sleep(wsClientReconnectDelay)
		synctest.Wait()
		if got := tokenCalls.Load(); got != 1 {
			t.Fatalf("token calls after retry = %d, want cached reuse", got)
		}
		select {
		case req := <-dialer.calls:
			if got := req.Header.Get("Authorization"); got != "Bearer preserved-token" {
				t.Fatalf("retry Authorization = %q", got)
			}
		default:
			t.Fatal("credential retry did not dial")
		}
		if !conn.IsConnected() {
			t.Fatal("credential retry did not install generation")
		}
	})
}

func TestManagedSupervisorParentCancelStopsRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		dialer.results <- supervisorTestDialResult{err: errors.New("dial failed")}
		defer installSupervisorTestDialer(dialer)()

		ctx, cancel := context.WithCancel(context.Background())
		conn := newSupervisorTestConn(ctx)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("initial dial calls = %d, want 1", got)
		}

		cancel()
		synctest.Wait()
		time.Sleep(10 * wsClientDialRetryDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 0 {
			t.Fatalf("dial calls after parent cancel = %d, want 0", got)
		}
		select {
		case <-conn.supervisorDone:
		default:
			t.Fatal("supervisor did not stop after parent cancel")
		}
		if conn.IsConnected() || conn.IsConnecting() {
			t.Fatal("canceled supervisor retained a live connection state")
		}
		conn.Close()
		conn.Close()
	})
}

func TestManagedSupervisorStateChangeWakesWaiterImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("initial dial calls = %d, want 1", got)
		}

		waitResult := make(chan error, 1)
		startedAt := time.Now()
		go func() {
			waitResult <- conn.WaitUntilConnected(context.Background())
		}()
		synctest.Wait()

		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		synctest.Wait()
		select {
		case err := <-waitResult:
			if err != nil {
				t.Fatalf("WaitUntilConnected() error = %v", err)
			}
		default:
			t.Fatal("state change did not wake WaitUntilConnected")
		}
		if elapsed := time.Since(startedAt); elapsed != 0 {
			t.Fatalf("state notification required polling time: %v", elapsed)
		}
	})
}

func TestManagedSupervisorHeartbeatRequiresTwoFullMissingPongWindows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		firstWire := newSupervisorTestWire()
		secondWire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: firstWire}
		dialer.results <- supervisorTestDialResult{wire: secondWire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("initial dial calls = %d, want 1", got)
		}

		time.Sleep(wsClientPingInterval - time.Nanosecond)
		synctest.Wait()
		requireNoSupervisorWrite(t, firstWire)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		requireSupervisorWrite(t, firstWire, websocket.TextMessage, "ping")

		time.Sleep(wsClientPingInterval)
		synctest.Wait()
		requireSupervisorWrite(t, firstWire, websocket.TextMessage, "ping")
		if !conn.IsConnected() {
			t.Fatal("connection ended after only one complete missing-pong window")
		}

		time.Sleep(wsClientPingInterval)
		synctest.Wait()
		if !firstWire.isClosed() || conn.IsConnected() {
			t.Fatal("connection did not end after two complete missing-pong windows")
		}
		if got := supervisorDialCallCount(dialer); got != 0 {
			t.Fatalf("reconnect started before retry delay: %d calls", got)
		}

		time.Sleep(wsClientReconnectDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("reconnect dial calls = %d, want 1", got)
		}
		if !conn.IsConnected() || secondWire.isClosed() {
			t.Fatal("replacement generation was not installed")
		}
	})
}

func TestManagedSupervisorLiteralCurrentPongResetsHeartbeat(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		time.Sleep(wsClientPingInterval)
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, "ping")
		wire.reads <- supervisorTestRead{data: "pong"}
		synctest.Wait()
		requireNoSupervisorReceive(t, conn)

		time.Sleep(wsClientPingInterval)
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, "ping")
		wire.reads <- supervisorTestRead{data: "pong\n"}
		synctest.Wait()
		requireSupervisorReceive(t, conn, "pong\n")

		time.Sleep(wsClientPingInterval)
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, "ping")
		if !conn.IsConnected() {
			t.Fatal("literal pong did not reset the missed-window count")
		}

		time.Sleep(wsClientPingInterval)
		synctest.Wait()
		if !wire.isClosed() || conn.IsConnected() {
			t.Fatal("non-literal pong unexpectedly reset the missed-window count")
		}
	})
}

func TestManagedSupervisorReadFailureReconnectsAndIgnoresStaleEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		firstWire := newSupervisorTestWire()
		secondWire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: firstWire}
		dialer.results <- supervisorTestDialResult{wire: secondWire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)
		firstDone := conn.getDoneChan()

		firstWire.reads <- supervisorTestRead{err: errors.New("read failed")}
		synctest.Wait()
		if !firstWire.isClosed() || conn.IsConnected() {
			t.Fatal("read failure did not end the active generation")
		}
		select {
		case <-firstDone:
		default:
			t.Fatal("read failure did not close generation Done")
		}

		time.Sleep(wsClientReconnectDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("reconnect dial calls = %d, want 1", got)
		}
		if !conn.IsConnected() {
			t.Fatal("read failure did not install a replacement generation")
		}
		secondDone := conn.getDoneChan()
		if secondDone == firstDone {
			t.Fatal("replacement generation reused the closed Done channel")
		}

		conn.readEvents <- wsReadEvent{generation: 1, data: []byte("stale")}
		conn.readEvents <- wsReadEvent{generation: 1, err: errors.New("stale read failure")}
		synctest.Wait()
		requireNoSupervisorReceive(t, conn)
		if !conn.IsConnected() {
			t.Fatal("stale generation event ended the current generation")
		}

		time.Sleep(wsClientPingInterval)
		synctest.Wait()
		requireSupervisorWrite(t, secondWire, websocket.TextMessage, "ping")
		conn.readEvents <- wsReadEvent{generation: 1, data: []byte("pong")}
		synctest.Wait()

		time.Sleep(2 * wsClientPingInterval)
		synctest.Wait()
		if !secondWire.isClosed() || conn.IsConnected() {
			t.Fatal("stale generation pong reset the current heartbeat")
		}
	})
}

func TestManagedSupervisorWriteFailureReportsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		wire.writeError = errors.New("write failed")
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "198.51.100.10"
		conn.MsgSendCh <- request
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)
		requireSupervisorReceive(t, conn, apiServerErrorMessage(request))
		requireNoSupervisorReceive(t, conn)
		if !wire.isClosed() || conn.IsConnected() {
			t.Fatal("write failure did not end the active generation")
		}
	})
}

func TestManagedSupervisorDoesNotReplayOldGenerationWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		writeGate := make(chan struct{})
		firstWire := newSupervisorTestWire()
		firstWire.writeGate = writeGate
		secondWire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: firstWire}
		dialer.results <- supervisorTestDialResult{wire: secondWire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.20"
		conn.MsgSendCh <- request
		synctest.Wait()
		requireSupervisorWrite(t, firstWire, websocket.TextMessage, request)

		firstWire.reads <- supervisorTestRead{err: errors.New("generation ended")}
		synctest.Wait()
		requireSupervisorReceive(t, conn, apiServerErrorMessage(request))
		requireNoSupervisorReceive(t, conn)

		time.Sleep(wsClientReconnectDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("reconnect dial calls = %d, want 1", got)
		}
		if !conn.IsConnected() {
			t.Fatal("replacement generation was not installed")
		}
		requireNoSupervisorWrite(t, secondWire)
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedSendMessageRejectsAfterClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)
		conn.Close()

		if err := conn.SendMessage(context.Background(), "192.0.2.10"); !errors.Is(err, errConnClosed) {
			t.Fatalf("SendMessage() error = %v, want %v", err, errConnClosed)
		}
		requireNoSupervisorWrite(t, wire)
	})
}

func TestManagedSendMessageDoesNotReplayAcceptedOldGenerationWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		writeGate := make(chan struct{})
		firstWire := newSupervisorTestWire()
		firstWire.writeGate = writeGate
		secondWire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: firstWire}
		dialer.results <- supervisorTestDialResult{wire: secondWire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.21"
		if err := conn.SendMessage(context.Background(), request); err != nil {
			t.Fatalf("SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, firstWire, websocket.TextMessage, request)

		firstWire.reads <- supervisorTestRead{err: errors.New("generation ended")}
		synctest.Wait()
		requireSupervisorReceive(t, conn, apiServerErrorMessage(request))
		requireNoSupervisorReceive(t, conn)

		time.Sleep(wsClientReconnectDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("reconnect dial calls = %d, want 1", got)
		}
		if !conn.IsConnected() {
			t.Fatal("replacement generation was not installed")
		}
		requireNoSupervisorWrite(t, secondWire)
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedRequestMessageIgnoresQueuedPreviousGenerationResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		firstWire := newSupervisorTestWire()
		secondWire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: firstWire}
		dialer.results <- supervisorTestDialResult{wire: secondWire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		for i := 0; i < cap(conn.MsgReceiveCh); i++ {
			conn.MsgReceiveCh <- fmt.Sprintf("queued-%d", i)
		}

		const request = "203.0.113.40"
		const oldResponse = `{"ip":"203.0.113.40","asnumber":"OLD"}`
		if err := conn.SendMessage(context.Background(), request); err != nil {
			t.Fatalf("SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, firstWire, websocket.TextMessage, request)
		firstWire.reads <- supervisorTestRead{data: oldResponse}
		synctest.Wait()

		firstWire.reads <- supervisorTestRead{err: errors.New("replace generation")}
		synctest.Wait()
		time.Sleep(wsClientReconnectDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("reconnect dial calls = %d, want 1", got)
		}

		type requestResult struct {
			response string
			err      error
		}
		done := make(chan requestResult, 1)
		go func() {
			response, err := conn.RequestMessage(context.Background(), request)
			done <- requestResult{response: response, err: err}
		}()
		synctest.Wait()
		requireSupervisorWrite(t, secondWire, websocket.TextMessage, request)

		<-conn.MsgReceiveCh
		synctest.Wait()
		sawOldResponse := false
		for i := 0; i < cap(conn.MsgReceiveCh); i++ {
			if got := <-conn.MsgReceiveCh; got == oldResponse {
				sawOldResponse = true
			}
		}
		if !sawOldResponse {
			t.Fatal("previous-generation response was not released from the public queue")
		}
		select {
		case got := <-done:
			t.Fatalf("previous-generation response completed current request: %+v", got)
		default:
		}

		const currentResponse = `{"ip":"203.0.113.40","asnumber":"CURRENT"}`
		secondWire.reads <- supervisorTestRead{data: currentResponse}
		synctest.Wait()
		got := <-done
		if got.err != nil || got.response != currentResponse {
			t.Fatalf("RequestMessage() = (%q, %v), want (%q, nil)", got.response, got.err, currentResponse)
		}
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedRequestMessageDoesNotConsumeLegacySameIPResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.44"
		conn.MsgSendCh <- request
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)

		type requestResult struct {
			response string
			err      error
		}
		done := make(chan requestResult, 1)
		go func() {
			response, err := conn.RequestMessage(context.Background(), request)
			done <- requestResult{response: response, err: err}
		}()
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)

		const legacyResponse = `{"ip":"203.0.113.44","asnumber":"LEGACY"}`
		wire.reads <- supervisorTestRead{data: legacyResponse}
		synctest.Wait()
		requireSupervisorReceive(t, conn, legacyResponse)
		select {
		case got := <-done:
			t.Fatalf("legacy response completed bound request: %+v", got)
		default:
		}

		const boundResponse = `{"ip":"203.0.113.44","asnumber":"BOUND"}`
		wire.reads <- supervisorTestRead{data: boundResponse}
		synctest.Wait()
		got := <-done
		if got.err != nil || got.response != boundResponse {
			t.Fatalf("RequestMessage() = (%q, %v), want (%q, nil)", got.response, got.err, boundResponse)
		}
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedRequestMessageGenerationFailureReturnsBoundAPIError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.41"
		done := make(chan struct {
			response string
			err      error
		}, 1)
		go func() {
			response, err := conn.RequestMessage(context.Background(), request)
			done <- struct {
				response string
				err      error
			}{response: response, err: err}
		}()
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)

		wire.reads <- supervisorTestRead{err: errors.New("request generation failed")}
		synctest.Wait()
		got := <-done
		want := apiServerErrorMessage(request)
		if got.err != nil || got.response != want {
			t.Fatalf("RequestMessage() = (%q, %v), want (%q, nil)", got.response, got.err, want)
		}
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedRequestMessageCancellationRotatesGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		firstWire := newSupervisorTestWire()
		secondWire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: firstWire}
		dialer.results <- supervisorTestDialResult{wire: secondWire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.42"
		requestCtx, cancelRequest := context.WithCancel(context.Background())
		firstDone := make(chan error, 1)
		go func() {
			_, err := conn.RequestMessage(requestCtx, request)
			firstDone <- err
		}()
		synctest.Wait()
		requireSupervisorWrite(t, firstWire, websocket.TextMessage, request)

		const peerRequest = "203.0.113.43"
		peerDone := make(chan struct {
			response string
			err      error
		}, 1)
		go func() {
			response, err := conn.RequestMessage(context.Background(), peerRequest)
			peerDone <- struct {
				response string
				err      error
			}{response: response, err: err}
		}()
		synctest.Wait()
		requireSupervisorWrite(t, firstWire, websocket.TextMessage, peerRequest)

		cancelRequest()
		synctest.Wait()
		if err := <-firstDone; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled RequestMessage() error = %v, want %v", err, context.Canceled)
		}
		peerResult := <-peerDone
		peerFailure := apiServerErrorMessage(peerRequest)
		if peerResult.err != nil || peerResult.response != peerFailure {
			t.Fatalf(
				"peer RequestMessage() = (%q, %v), want (%q, nil)",
				peerResult.response,
				peerResult.err,
				peerFailure,
			)
		}
		requireNoSupervisorReceive(t, conn)
		if !firstWire.isClosed() || conn.IsConnected() {
			t.Fatal("canceling a bound request did not retire its generation")
		}

		time.Sleep(wsClientReconnectDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("reconnect dial calls = %d, want 1", got)
		}

		type requestResult struct {
			response string
			err      error
		}
		secondDone := make(chan requestResult, 1)
		go func() {
			response, err := conn.RequestMessage(context.Background(), request)
			secondDone <- requestResult{response: response, err: err}
		}()
		synctest.Wait()
		requireSupervisorWrite(t, secondWire, websocket.TextMessage, request)

		conn.readEvents <- wsReadEvent{
			generation: 1,
			data:       []byte(`{"ip":"203.0.113.42","asnumber":"STALE"}`),
		}
		synctest.Wait()
		select {
		case got := <-secondDone:
			t.Fatalf("canceled generation response completed replacement request: %+v", got)
		default:
		}

		const currentResponse = `{"ip":"203.0.113.42","asnumber":"CURRENT"}`
		secondWire.reads <- supervisorTestRead{data: currentResponse}
		synctest.Wait()
		got := <-secondDone
		if got.err != nil || got.response != currentResponse {
			t.Fatalf("replacement RequestMessage() = (%q, %v), want (%q, nil)", got.response, got.err, currentResponse)
		}
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedCloseDeliversAcceptedPendingFailureBeforeClosingReceive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		writeGate := make(chan struct{})
		wire := newSupervisorTestWire()
		wire.writeGate = writeGate
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.22"
		if err := conn.SendMessage(context.Background(), request); err != nil {
			t.Fatalf("SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)

		conn.Close()
		got, ok := <-conn.MsgReceiveCh
		if !ok || got != apiServerErrorMessage(request) {
			t.Fatalf("pending failure = (%q, %v), want (%q, true)", got, ok, apiServerErrorMessage(request))
		}
		if _, ok := <-conn.MsgReceiveCh; ok {
			t.Fatal("MsgReceiveCh remained open after pending failure was delivered")
		}
	})
}

func TestManagedSupervisorResponseSettlesPendingBeforeGenerationEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		writeGate := make(chan struct{})
		wire := newSupervisorTestWire()
		wire.writeGate = writeGate
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.24"
		const response = `{"ip":"203.0.113.24","asnumber":"64500"}`
		if err := conn.SendMessage(context.Background(), request); err != nil {
			t.Fatalf("SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)

		wire.reads <- supervisorTestRead{data: response}
		synctest.Wait()
		requireSupervisorReceive(t, conn, response)
		wire.reads <- supervisorTestRead{err: errors.New("connection ended after response")}
		synctest.Wait()
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedSendMessageWrittenBeforeResponseFailsOnceOnGenerationEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.28"
		if err := conn.SendMessage(context.Background(), request); err != nil {
			t.Fatalf("SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)
		wire.reads <- supervisorTestRead{err: errors.New("connection ended before response")}
		synctest.Wait()
		requireSupervisorReceive(t, conn, apiServerErrorMessage(request))
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedSendMessageContextCancelRetiresWrittenGenerationSilently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		requestCtx, cancelRequest := context.WithCancel(context.Background())
		const request = "203.0.113.29"
		if err := conn.SendMessage(requestCtx, request); err != nil {
			t.Fatalf("SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)
		cancelRequest()
		synctest.Wait()
		requireNoSupervisorReceive(t, conn)
		if !wire.isClosed() || conn.IsConnected() {
			t.Fatal("canceling a written SendMessage did not retire its generation")
		}
	})
}

func TestManagedWriterSkipsQueuedCanceledSendMessage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		writeGate := make(chan struct{})
		wire := newSupervisorTestWire()
		wire.writeGate = writeGate
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const firstRequest = "203.0.113.35"
		if err := conn.SendMessage(context.Background(), firstRequest); err != nil {
			t.Fatalf("first SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, firstRequest)

		requestCtx, cancelRequest := context.WithCancel(context.Background())
		const canceledRequest = "203.0.113.36"
		if err := conn.SendMessage(requestCtx, canceledRequest); err != nil {
			t.Fatalf("second SendMessage() error = %v", err)
		}
		cancelRequest()
		synctest.Wait()
		close(writeGate)
		synctest.Wait()

		requireNoSupervisorWrite(t, wire)
		requireNoSupervisorReceive(t, conn)
		if !conn.IsConnected() || wire.isClosed() {
			t.Fatal("skipping canceled queued request changed connection health")
		}
	})
}

func TestManagedLegacyWriteSuccessDoesNotAwaitResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.30"
		conn.MsgSendCh <- request
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)
		wire.reads <- supervisorTestRead{err: errors.New("connection ended after legacy write")}
		synctest.Wait()
		requireNoSupervisorReceive(t, conn)
	})
}

func TestLegacyGenerationCleanupObservesWriterSuccessBeforeWriteResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rootCtx, cancelRoot := context.WithCancel(context.Background())
		wire := newSupervisorTestWire()
		conn := &WsConn{
			MsgReceiveCh:   make(chan string, 1),
			closeCh:        make(chan struct{}),
			rootCtx:        rootCtx,
			managedWriteCh: make(chan wsWriteJob, 1),
			writeResults:   make(chan wsWriteResult, 1),
		}
		conn.workerWG.Add(1)
		go conn.managedWriteLoop()

		progress := &wsWriteProgress{}
		job := wsWriteJob{
			id:         1,
			generation: 1,
			wire:       wire,
			kind:       wsWriteRequest,
			msgType:    websocket.TextMessage,
			data:       []byte("203.0.113.45"),
			requestIP:  "203.0.113.45",
			progress:   progress,
		}
		conn.managedWriteCh <- job
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, job.requestIP)
		if !progress.succeeded.Load() || len(conn.writeResults) != 1 {
			t.Fatal("writer success was not published before its queued result")
		}

		state := wsSupervisorState{pending: map[uint64]wsWriteJob{job.id: job}}
		conn.failPendingGeneration(&state, job.generation)
		if len(state.pending) != 0 {
			t.Fatal("successful legacy marker remained pending after generation cleanup")
		}
		requireNoSupervisorReceive(t, conn)

		cancelRoot()
		synctest.Wait()
		conn.workerWG.Wait()
	})
}

func TestManagedCloseStopsAwaitResponseWatchers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		for _, request := range []string{"203.0.113.31", "203.0.113.32", "203.0.113.33", "203.0.113.34"} {
			if err := conn.SendMessage(context.Background(), request); err != nil {
				t.Fatalf("SendMessage(%q) error = %v", request, err)
			}
		}
		synctest.Wait()

		closed := make(chan struct{})
		go func() {
			conn.Close()
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("Close blocked with await-response context watchers")
		}
	})
}

func TestManagedSupervisorResponseReadFailureThenWriteSuccessDoesNotFailRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		writeGate := make(chan struct{})
		wire := newSupervisorTestWire()
		wire.writeGate = writeGate
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.25"
		const response = `{"ip":"203.0.113.25","asnumber":"64501"}`
		if err := conn.SendMessage(context.Background(), request); err != nil {
			t.Fatalf("SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, wire, websocket.TextMessage, request)

		wire.reads <- supervisorTestRead{data: response}
		synctest.Wait()
		requireSupervisorReceive(t, conn, response)
		wire.reads <- supervisorTestRead{err: errors.New("read failed after response")}
		synctest.Wait()
		conn.writeResults <- wsWriteResult{job: wsWriteJob{
			id:         1,
			generation: 1,
			kind:       wsWriteRequest,
			requestIP:  request,
		}}
		synctest.Wait()
		requireNoSupervisorReceive(t, conn)
	})
}

func TestManagedSupervisorResponseThenWriteFailureReconnectsWithoutDuplicateError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		writeGate := make(chan struct{})
		firstWire := newSupervisorTestWire()
		firstWire.writeGate = writeGate
		firstWire.writeError = errors.New("write failed after response")
		secondWire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: firstWire}
		dialer.results <- supervisorTestDialResult{wire: secondWire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		defer conn.Close()
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const request = "203.0.113.27"
		const response = `{"ip":"203.0.113.27","asnumber":"64502"}`
		if err := conn.SendMessage(context.Background(), request); err != nil {
			t.Fatalf("SendMessage() error = %v", err)
		}
		synctest.Wait()
		requireSupervisorWrite(t, firstWire, websocket.TextMessage, request)

		firstWire.reads <- supervisorTestRead{data: response}
		synctest.Wait()
		requireSupervisorReceive(t, conn, response)
		close(writeGate)
		synctest.Wait()
		requireNoSupervisorReceive(t, conn)
		if !firstWire.isClosed() || conn.IsConnected() {
			t.Fatal("write failure after response did not end the active generation")
		}

		time.Sleep(wsClientReconnectDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("reconnect dial calls = %d, want 1", got)
		}
		if !conn.IsConnected() || secondWire.isClosed() {
			t.Fatal("write failure after response did not install a replacement generation")
		}
	})
}

func TestCompletePendingResponseUsesOldestMatchingRequest(t *testing.T) {
	state := wsSupervisorState{pending: map[uint64]wsWriteJob{
		2: {id: 2, generation: 1, requestIP: "192.0.2.1"},
		3: {id: 3, generation: 1, requestIP: "192.0.2.2"},
		4: {id: 4, generation: 1, requestIP: "192.0.2.1"},
		5: {id: 5, generation: 2, requestIP: "192.0.2.1"},
	}}

	(&WsConn{}).completePendingResponse(&state, 1, []byte(`{"ip":"192.0.2.1"}`))
	if _, ok := state.pending[2]; ok {
		t.Fatal("oldest matching pending request was not completed")
	}
	for _, id := range []uint64{3, 4, 5} {
		if _, ok := state.pending[id]; !ok {
			t.Fatalf("pending request %d was completed unexpectedly", id)
		}
	}
}

func TestRegisterRequestBoundsPendingMarkers(t *testing.T) {
	pending := make(map[uint64]wsWriteJob, wsClientWriteQueueSize)
	for id := uint64(1); id <= wsClientWriteQueueSize; id++ {
		pending[id] = wsWriteJob{id: id, generation: 1}
	}
	state := wsSupervisorState{
		generation: &wsGeneration{id: 1},
		pending:    pending,
	}
	conn := &WsConn{rootCtx: context.Background()}

	err := conn.registerRequest(&state, "192.0.2.100", nil, false, nil)
	if !errors.Is(err, errWriteQueueFull) {
		t.Fatalf("registerRequest() error = %v, want %v", err, errWriteQueueFull)
	}
	if got := len(state.pending); got != wsClientWriteQueueSize {
		t.Fatalf("pending markers = %d, want %d", got, wsClientWriteQueueSize)
	}
}

func TestManagedSupervisorCloseWinsReconnectRace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		dialer.results <- supervisorTestDialResult{err: errors.New("dial failed")}
		defer installSupervisorTestDialer(dialer)()

		ctx, cancel := context.WithCancel(context.Background())
		conn := newSupervisorTestConn(ctx)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("initial dial calls = %d, want 1", got)
		}

		time.Sleep(wsClientDialRetryDelay)
		synctest.Wait()
		if got := supervisorDialCallCount(dialer); got != 1 {
			t.Fatalf("blocked retry dial calls = %d, want 1", got)
		}

		closed := make(chan struct{}, 2)
		go func() {
			conn.Close()
			closed <- struct{}{}
		}()
		go func() {
			conn.Close()
			closed <- struct{}{}
		}()
		cancel()
		synctest.Wait()
		if len(closed) != 2 {
			t.Fatalf("completed Close calls = %d, want 2", len(closed))
		}
		if conn.IsConnected() || conn.IsConnecting() {
			t.Fatal("shutdown/reconnect race retained a live state")
		}
		select {
		case <-conn.supervisorDone:
		default:
			t.Fatal("supervisor did not finish during shutdown/reconnect race")
		}
		conn.Close()
	})
}

func TestManagedSupervisorSlowConsumerDoesNotBlockShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		for i := 0; i < wsClientReceiveBacklog+64; i++ {
			wire.reads <- supervisorTestRead{data: "queued"}
		}
		synctest.Wait()

		closed := make(chan struct{}, 1)
		go func() {
			conn.Close()
			closed <- struct{}{}
		}()
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("slow receive consumer blocked shutdown")
		}
		if !wire.isClosed() {
			t.Fatal("shutdown did not close the active wire")
		}
		select {
		case <-conn.supervisorDone:
		default:
			t.Fatal("supervisor did not finish with a slow consumer")
		}
		conn.Close()
	})
}

func TestManagedSupervisorBackpressuresWithoutDroppingResponses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialer := newSupervisorTestDialer()
		wire := newSupervisorTestWire()
		dialer.results <- supervisorTestDialResult{wire: wire}
		defer installSupervisorTestDialer(dialer)()

		conn := newSupervisorTestConn(context.Background())
		synctest.Wait()
		_ = supervisorDialCallCount(dialer)

		const extra = 64
		const total = wsClientReceiveBacklog + extra
		for i := range total {
			wire.reads <- supervisorTestRead{data: fmt.Sprintf("response-%04d", i)}
		}
		synctest.Wait()

		received := make([]string, 0, total)
		drained := make(chan struct{})
		go func() {
			for range total {
				received = append(received, <-conn.MsgReceiveCh)
			}
			close(drained)
		}()
		synctest.Wait()
		select {
		case <-drained:
		default:
			t.Fatal("backpressured responses did not drain")
		}
		for i, got := range received {
			want := fmt.Sprintf("response-%04d", i)
			if got != want {
				t.Fatalf("response %d = %q, want %q", i, got, want)
			}
		}

		closed := make(chan struct{})
		go func() {
			conn.Close()
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("shutdown blocked after receive backpressure recovered")
		}
	})
}
