package wshandle

// Tests in this file mutate package-level websocket globals; do not add
// t.Parallel without isolating that state first.

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/util"
)

func TestFormatHostPort(t *testing.T) {
	tests := []struct {
		name string
		addr string
		port string
		want string
	}{
		{name: "IPv4", addr: " 192.0.2.1 ", port: "443", want: "192.0.2.1:443"},
		{name: "IPv6", addr: "2001:db8::1", port: "443", want: "[2001:db8::1]:443"},
		{name: "bracketed IPv6", addr: "[2001:db8::1]", port: "443", want: "[2001:db8::1]:443"},
		{name: "IPv6 zone", addr: "fe80::1%en0", port: "443", want: "[fe80::1%en0]:443"},
		{name: "empty host", addr: "", port: "443", want: ":443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatHostPort(tt.addr, tt.port); got != tt.want {
				t.Fatalf("formatHostPort(%q, %q) = %q, want %q", tt.addr, tt.port, got, tt.want)
			}
		})
	}
}

func newLiteralTestWsConn(ctx context.Context) *WsConn {
	return &WsConn{
		MsgSendCh:    make(chan string, 10),
		MsgReceiveCh: make(chan string, 10),
		Done:         make(chan struct{}),
		Interrupt:    make(chan os.Signal, 1),
		baseCtx:      normalizeContext(ctx),
	}
}

func waitForConnected(t *testing.T, conn *WsConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := conn.WaitUntilConnected(ctx); err != nil {
		t.Fatalf("WaitUntilConnected() error = %v", err)
	}
}

func saveAndRestoreGlobalWsConn(t *testing.T) {
	t.Helper()

	wsconnMu.RLock()
	oldWsconn := wsconn
	wsconnMu.RUnlock()

	t.Cleanup(func() {
		wsconnMu.Lock()
		current := wsconn
		wsconn = oldWsconn
		wsconnMu.Unlock()
		if current != nil && current != oldWsconn {
			current.Close()
		}
	})
}

func TestWsConnCloseIsIdempotent(t *testing.T) {
	dialer := newSupervisorTestDialer()
	wire := newSupervisorTestWire()
	dialer.results <- supervisorTestDialResult{wire: wire}
	defer installSupervisorTestDialer(dialer)()

	conn := newSupervisorTestConn(context.Background())
	waitForConnected(t, conn)
	doneCh := conn.getDoneChan()

	conn.Close()
	conn.Close()

	if !conn.isClosed() {
		t.Fatal("connection should be marked closed")
	}
	if !wire.isClosed() {
		t.Fatal("Close should close the active websocket generation")
	}
	select {
	case <-doneCh:
	default:
		t.Fatal("Done should be closed before Close returns")
	}
	select {
	case _, ok := <-conn.MsgReceiveCh:
		if ok {
			t.Fatal("MsgReceiveCh should be closed")
		}
	default:
		t.Fatal("MsgReceiveCh should be closed before Close returns")
	}
}

func TestZeroValueWsConnCanBeClosed(t *testing.T) {
	var conn WsConn
	conn.Close()
	conn.Close()
	if !conn.isClosed() {
		t.Fatal("zero-value connection should be closed")
	}
	if err := conn.WaitUntilConnected(context.Background()); !errors.Is(err, errConnClosed) {
		t.Fatalf("WaitUntilConnected() error = %v, want %v", err, errConnClosed)
	}
}

func TestNewClosesPreviousGlobalWsConn(t *testing.T) {
	oldCreateFn := createWsConnFn
	defer func() { createWsConnFn = oldCreateFn }()
	saveAndRestoreGlobalWsConn(t)

	oldConn := newLiteralTestWsConn(context.Background())
	wsconnMu.Lock()
	wsconn = oldConn
	wsconnMu.Unlock()

	newConn := newLiteralTestWsConn(context.Background())
	createWsConnFn = func(context.Context) *WsConn { return newConn }

	got := New()
	defer got.Close()
	if got != newConn || GetWsConn() != newConn {
		t.Fatal("New should publish and return the replacement connection")
	}
	if !oldConn.isClosed() {
		t.Fatal("previous global connection should be closed")
	}
}

func TestReplaceGlobalWsConnKeepsOldConnForCanceledContext(t *testing.T) {
	saveAndRestoreGlobalWsConn(t)
	oldConn := newLiteralTestWsConn(context.Background())
	wsconnMu.Lock()
	wsconn = oldConn
	wsconnMu.Unlock()

	newConn := newLiteralTestWsConn(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := replaceGlobalWsConn(newConn, ctx)
	if got != oldConn || GetWsConn() != oldConn {
		t.Fatal("canceled replacement should keep the existing connection")
	}
	if oldConn.isClosed() {
		t.Fatal("existing connection should remain open")
	}
	if !newConn.isClosed() {
		t.Fatal("rejected replacement should be closed")
	}
}

func TestReplaceGlobalWsConnDoesNotRewriteBaseContext(t *testing.T) {
	saveAndRestoreGlobalWsConn(t)
	originalCtx, originalCancel := context.WithCancel(context.Background())
	defer originalCancel()
	replacementCtx, replacementCancel := context.WithCancel(context.Background())
	defer replacementCancel()

	newConn := newLiteralTestWsConn(originalCtx)
	got := replaceGlobalWsConn(newConn, replacementCtx)
	defer got.Close()
	if got != newConn {
		t.Fatal("replaceGlobalWsConn should install the supplied connection")
	}
	if newConn.baseCtx != originalCtx {
		t.Fatal("replaceGlobalWsConn should not rewrite baseCtx")
	}
}

type blockingCloseWire struct {
	closeStarted chan struct{}
	releaseClose chan struct{}
	readDone     chan struct{}
	closeOnce    sync.Once
}

func newBlockingCloseWire() *blockingCloseWire {
	return &blockingCloseWire{
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
		readDone:     make(chan struct{}),
	}
}

func (w *blockingCloseWire) ReadMessage() (int, []byte, error) {
	<-w.readDone
	return 0, nil, errSupervisorTestWireClosed
}

func (*blockingCloseWire) SetWriteDeadline(time.Time) error { return nil }

func (*blockingCloseWire) WriteMessage(int, []byte) error { return nil }

func (w *blockingCloseWire) Close() error {
	w.closeOnce.Do(func() {
		close(w.closeStarted)
		<-w.releaseClose
		close(w.readDone)
	})
	return nil
}

func TestGetWsConnDoesNotBlockWhileNewClosesPreviousConn(t *testing.T) {
	oldCreateFn := createWsConnFn
	defer func() { createWsConnFn = oldCreateFn }()
	saveAndRestoreGlobalWsConn(t)

	dialer := newSupervisorTestDialer()
	oldWire := newBlockingCloseWire()
	dialer.results <- supervisorTestDialResult{wire: oldWire}
	defer installSupervisorTestDialer(dialer)()
	oldConn := newSupervisorTestConn(context.Background())
	waitForConnected(t, oldConn)
	wsconnMu.Lock()
	wsconn = oldConn
	wsconnMu.Unlock()

	newConn := newLiteralTestWsConn(context.Background())
	createWsConnFn = func(context.Context) *WsConn { return newConn }
	newResult := make(chan *WsConn, 1)
	go func() { newResult <- New() }()

	select {
	case <-oldWire.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("New did not start closing the previous connection")
	}
	if got := GetWsConn(); got != newConn {
		t.Fatalf("GetWsConn() = %p, want %p while old Close is blocked", got, newConn)
	}
	close(oldWire.releaseClose)
	select {
	case got := <-newResult:
		if got != newConn {
			t.Fatalf("New() = %p, want %p", got, newConn)
		}
	case <-time.After(time.Second):
		t.Fatal("New did not finish after old Close was released")
	}
}

func TestCreateWsConnHonorsCanceledContextDuringFastIP(t *testing.T) {
	oldFastIPFn := wsGetFastIPFn
	oldHostPort := util.EnvHostPort
	defer func() {
		wsGetFastIPFn = oldFastIPFn
		util.EnvHostPort = oldHostPort
	}()
	util.EnvHostPort = "example.com:443"

	started := make(chan struct{})
	wsGetFastIPFn = func(ctx context.Context, domain, port string, enableOutput bool) (string, error) {
		close(started)
		<-ctx.Done()
		return "", ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *WsConn, 1)
	go func() { done <- createWsConn(ctx) }()
	<-started
	cancel()

	select {
	case conn := <-done:
		if conn == nil || conn.IsConnected() {
			t.Fatalf("createWsConn() = %#v after cancellation", conn)
		}
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("createWsConn did not return after context cancellation")
	}
}

func TestCreateWsConnAsyncReturnsBeforeFastIP(t *testing.T) {
	oldFastIPFn := wsGetFastIPFn
	oldHostPort := util.EnvHostPort
	defer func() {
		wsGetFastIPFn = oldFastIPFn
		util.EnvHostPort = oldHostPort
	}()
	util.EnvHostPort = "example.com:443"

	fastIPStarted := make(chan struct{}, 1)
	fastIPDone := make(chan struct{}, 1)
	releaseFastIP := make(chan struct{})
	wsGetFastIPFn = func(ctx context.Context, domain, port string, enableOutput bool) (string, error) {
		fastIPStarted <- struct{}{}
		defer func() { fastIPDone <- struct{}{} }()
		select {
		case <-releaseFastIP:
			return "192.0.2.1", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	returned := make(chan *WsConn, 1)
	go func() { returned <- createWsConnAsync(context.Background()) }()
	select {
	case <-fastIPStarted:
	case <-time.After(time.Second):
		t.Fatal("FastIP probe did not start")
	}
	select {
	case conn := <-returned:
		conn.Close()
	case <-fastIPDone:
		t.Fatal("createWsConnAsync waited for FastIP")
	case <-time.After(time.Second):
		t.Fatal("createWsConnAsync did not return")
	}
	close(releaseFastIP)
}

func TestWaitUntilConnectedSupportsStructLiteral(t *testing.T) {
	conn := newLiteralTestWsConn(context.Background())
	defer conn.Close()
	done := make(chan error, 1)
	go func() { done <- conn.WaitUntilConnected(context.Background()) }()
	conn.SetConnected(true)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitUntilConnected() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetConnected did not wake WaitUntilConnected")
	}
}

func TestWaitUntilConnectedHonorsContext(t *testing.T) {
	conn := newLiteralTestWsConn(context.Background())
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := conn.WaitUntilConnected(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitUntilConnected() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestWsConnSuppressCanceledContextLogTreatsDeadlineAsStop(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	conn := newLiteralTestWsConn(ctx)
	defer conn.Close()
	if !conn.suppressCanceledContextLog(errors.New("dial failed")) {
		t.Fatal("canceled base context should suppress connection errors")
	}
	if !conn.suppressCanceledContextLog(context.DeadlineExceeded) {
		t.Fatal("deadline errors should be suppressed")
	}
}

func TestCreateWsConnAsyncPreservesDirectIPEndpointAndHeaders(t *testing.T) {
	oldFastIPFn := wsGetFastIPFn
	oldHostPort := util.EnvHostPort
	defer func() {
		wsGetFastIPFn = oldFastIPFn
		util.EnvHostPort = oldHostPort
	}()
	util.EnvHostPort = "192.0.2.10:8443"

	var fastIPCalls atomic.Int32
	wsGetFastIPFn = func(context.Context, string, string, bool) (string, error) {
		fastIPCalls.Add(1)
		return "", errors.New("unexpected FastIP lookup")
	}
	dialer := newSupervisorTestDialer()
	wire := newSupervisorTestWire()
	dialer.results <- supervisorTestDialResult{wire: wire}
	defer installSupervisorTestDialer(dialer)()

	conn := createWsConnAsync(context.Background())
	defer conn.Close()
	waitForConnected(t, conn)
	if !conn.directIP || conn.apiFastIP != "192.0.2.10" {
		t.Fatalf("direct endpoint = (%v, %q), want (true, 192.0.2.10)", conn.directIP, conn.apiFastIP)
	}
	if got := fastIPCalls.Load(); got != 0 {
		t.Fatalf("FastIP calls = %d, want 0 for direct endpoint", got)
	}

	var req wsDialRequest
	select {
	case req = <-dialer.calls:
	case <-time.After(time.Second):
		t.Fatal("missing websocket dial request")
	}
	if req.URL != "wss://192.0.2.10:8443/v3/ipGeoWs" {
		t.Fatalf("dial URL = %q", req.URL)
	}
	if req.ServerName != "api.nxtrace.org" || req.Header.Get("Host") != "api.nxtrace.org" {
		t.Fatalf("SNI/Host = (%q, %q)", req.ServerName, req.Header.Get("Host"))
	}
	if got := req.Header.Get("Authorization"); got != "Bearer supervisor-test-token" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := req.Header.Get("User-Agent"); got != "Privileged Client" {
		t.Fatalf("User-Agent = %q", got)
	}
}

func TestCreateWsConnSyncRefreshesCachedToken(t *testing.T) {
	oldDialFn := wsDialFn
	oldTokenFn := wsGetTokenFn
	oldEnvToken := envToken
	oldHostPort := util.EnvHostPort
	oldCacheToken := loadCachedToken()
	defer func() {
		wsDialFn = oldDialFn
		wsGetTokenFn = oldTokenFn
		envToken = oldEnvToken
		util.EnvHostPort = oldHostPort
		storeCachedToken(oldCacheToken)
	}()

	util.EnvHostPort = "192.0.2.10:443"
	envToken = ""
	storeCachedToken("stale-token")
	var tokenCalls atomic.Int32
	wsGetTokenFn = func(context.Context, string, string, string) (string, error) {
		tokenCalls.Add(1)
		return "fresh-token", nil
	}
	dialer := newSupervisorTestDialer()
	wire := newSupervisorTestWire()
	dialer.results <- supervisorTestDialResult{wire: wire}
	wsDialFn = dialer.dial

	conn := createWsConn(context.Background())
	defer conn.Close()
	if !conn.IsConnected() || conn.IsConnecting() {
		t.Fatal("synchronous create returned before successful state was published")
	}
	if got := tokenCalls.Load(); got != 1 {
		t.Fatalf("token calls = %d, want 1", got)
	}
	select {
	case req := <-dialer.calls:
		if got := req.Header.Get("Authorization"); got != "Bearer fresh-token" {
			t.Fatalf("Authorization = %q, want fresh token", got)
		}
	case <-time.After(time.Second):
		t.Fatal("missing websocket dial request")
	}
}

func TestCreateWsConnAsyncReusesCachedToken(t *testing.T) {
	oldDialFn := wsDialFn
	oldTokenFn := wsGetTokenFn
	oldEnvToken := envToken
	oldHostPort := util.EnvHostPort
	oldCacheToken := loadCachedToken()
	defer func() {
		wsDialFn = oldDialFn
		wsGetTokenFn = oldTokenFn
		envToken = oldEnvToken
		util.EnvHostPort = oldHostPort
		storeCachedToken(oldCacheToken)
	}()

	util.EnvHostPort = "192.0.2.10:443"
	envToken = ""
	storeCachedToken("cached-token")
	var tokenCalls atomic.Int32
	wsGetTokenFn = func(context.Context, string, string, string) (string, error) {
		tokenCalls.Add(1)
		return "unexpected-token", nil
	}
	dialer := newSupervisorTestDialer()
	wire := newSupervisorTestWire()
	dialer.results <- supervisorTestDialResult{wire: wire}
	wsDialFn = dialer.dial

	conn := createWsConnAsync(context.Background())
	defer conn.Close()
	waitForConnected(t, conn)
	if got := tokenCalls.Load(); got != 0 {
		t.Fatalf("token calls = %d, want 0", got)
	}
	select {
	case req := <-dialer.calls:
		if got := req.Header.Get("Authorization"); got != "Bearer cached-token" {
			t.Fatalf("Authorization = %q, want cached token", got)
		}
	case <-time.After(time.Second):
		t.Fatal("missing websocket dial request")
	}
}

func TestFreshCredentialFailurePreservesCachedToken(t *testing.T) {
	oldTokenFn := wsGetTokenFn
	oldEnvToken := envToken
	oldCacheToken := loadCachedToken()
	defer func() {
		wsGetTokenFn = oldTokenFn
		envToken = oldEnvToken
		storeCachedToken(oldCacheToken)
	}()

	envToken = ""
	storeCachedToken("retry-token")
	wsGetTokenFn = func(context.Context, string, string, string) (string, error) {
		return "", errors.New("fresh token failed")
	}
	if _, _, err := websocketCredentials(context.Background(), "192.0.2.1", "api.nxtrace.org", "443", false); err == nil {
		t.Fatal("fresh credential lookup unexpectedly succeeded")
	}
	if got := loadCachedToken(); got != "retry-token" {
		t.Fatalf("cached token = %q, want preserved retry token", got)
	}
}

func TestCreateWsConnSyncReturnsAfterFailedStatePublished(t *testing.T) {
	oldHostPort := util.EnvHostPort
	defer func() { util.EnvHostPort = oldHostPort }()
	util.EnvHostPort = "192.0.2.10:443"

	dialer := newSupervisorTestDialer()
	dialer.results <- supervisorTestDialResult{err: errors.New("dial failed")}
	defer installSupervisorTestDialer(dialer)()

	conn := createWsConn(context.Background())
	defer conn.Close()
	connected, phase, _, _ := conn.stateSnapshot()
	if connected || conn.IsConnecting() || phase != wsPhaseRetryWait {
		t.Fatalf("sync failure state = (connected=%v, connecting=%v, phase=%v), want retry wait", connected, conn.IsConnecting(), phase)
	}
}

func TestDialFailurePanicPolicy(t *testing.T) {
	syncConn := &WsConn{syncFirstAttempt: true}
	asyncConn := &WsConn{}
	tests := []struct {
		name   string
		conn   *WsConn
		result wsDialResult
		want   bool
	}{
		{name: "sync initial FastIP", conn: syncConn, result: wsDialResult{attemptID: 1, stage: wsDialStageFastIP}, want: true},
		{name: "async initial FastIP", conn: asyncConn, result: wsDialResult{attemptID: 1, stage: wsDialStageFastIP}},
		{name: "sync retry FastIP", conn: syncConn, result: wsDialResult{attemptID: 2, stage: wsDialStageFastIP}},
		{name: "sync initial token", conn: syncConn, result: wsDialResult{attemptID: 1, stage: wsDialStageToken}, want: true},
		{name: "async initial token", conn: asyncConn, result: wsDialResult{attemptID: 1, stage: wsDialStageToken}, want: true},
		{name: "retry token", conn: syncConn, result: wsDialResult{attemptID: 2, stage: wsDialStageToken}, want: true},
		{name: "connect", conn: syncConn, result: wsDialResult{attemptID: 1, stage: wsDialStageConnect}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.conn.shouldPanicDialFailure(tt.result); got != tt.want {
				t.Fatalf("shouldPanicDialFailure() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateWsConnSyncDevModeFailurePanicsInCaller(t *testing.T) {
	oldFastIPFn := wsGetFastIPFn
	oldTokenFn := wsGetTokenFn
	oldEnvToken := envToken
	oldHostPort := util.EnvHostPort
	oldDevMode := util.EnvDevMode
	oldCacheToken := loadCachedToken()
	defer func() {
		wsGetFastIPFn = oldFastIPFn
		wsGetTokenFn = oldTokenFn
		envToken = oldEnvToken
		util.EnvHostPort = oldHostPort
		util.EnvDevMode = oldDevMode
		storeCachedToken(oldCacheToken)
	}()

	util.EnvDevMode = true
	envToken = ""
	wantErr := errors.New("initial development failure")
	tests := []struct {
		name  string
		setup func()
	}{
		{
			name: "FastIP",
			setup: func() {
				util.EnvHostPort = "example.com:443"
				wsGetFastIPFn = func(context.Context, string, string, bool) (string, error) {
					return "", wantErr
				}
			},
		},
		{
			name: "token",
			setup: func() {
				util.EnvHostPort = "192.0.2.10:443"
				wsGetTokenFn = func(context.Context, string, string, string) (string, error) {
					return "", wantErr
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			if got := recoverCreateWsConnPanic(); got != wantErr {
				t.Fatalf("createWsConn() panic = %v, want %v", got, wantErr)
			}
		})
	}
}

func recoverCreateWsConnPanic() (recovered any) {
	defer func() {
		recovered = recover()
	}()
	_ = createWsConn(context.Background())
	return nil
}

func TestFastIPFailureLogPreservesInitialProbeWording(t *testing.T) {
	oldOutput := log.Writer()
	oldFlags := log.Flags()
	defer func() {
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
	}()
	log.SetFlags(0)

	var output bytes.Buffer
	log.SetOutput(&output)
	errProbe := errors.New("lookup failed")
	(&WsConn{syncFirstAttempt: true}).logDialFailure(wsDialResult{
		attemptID: 1,
		stage:     wsDialStageFastIP,
		err:       errProbe,
	})
	if got := strings.TrimSpace(output.String()); got != "fast ip probe failed: lookup failed" {
		t.Fatalf("sync FastIP log = %q", got)
	}

	output.Reset()
	(&WsConn{}).logDialFailure(wsDialResult{
		attemptID: 1,
		stage:     wsDialStageFastIP,
		err:       errProbe,
	})
	if got := strings.TrimSpace(output.String()); got != "fast ip refresh failed: lookup failed" {
		t.Fatalf("async FastIP log = %q", got)
	}
}

func TestLiteralWsConnSendMessageFallback(t *testing.T) {
	conn := newLiteralTestWsConn(context.Background())
	if err := conn.SendMessage(context.Background(), "192.0.2.20"); err != nil {
		t.Fatalf("SendMessage() error = %v", err)
	}
	select {
	case got := <-conn.MsgSendCh:
		if got != "192.0.2.20" {
			t.Fatalf("fallback message = %q", got)
		}
	default:
		t.Fatal("literal fallback did not enqueue message")
	}
	conn.Close()
	if err := conn.SendMessage(context.Background(), "192.0.2.21"); !errors.Is(err, errConnClosed) {
		t.Fatalf("SendMessage() after Close error = %v, want %v", err, errConnClosed)
	}
}

func TestLiteralWsConnRequestMessageIsUnsupportedWithoutSideEffects(t *testing.T) {
	conn := &WsConn{
		MsgSendCh:    make(chan string, 1),
		MsgReceiveCh: make(chan string, 1),
	}

	response, err := conn.RequestMessage(context.Background(), "192.0.2.23")
	if !errors.Is(err, ErrRequestResponseUnsupported) || response != "" {
		t.Fatalf("RequestMessage() = (%q, %v), want empty unsupported result", response, err)
	}
	select {
	case sent := <-conn.MsgSendCh:
		t.Fatalf("unsupported RequestMessage() sent %q", sent)
	default:
	}
	select {
	case received := <-conn.MsgReceiveCh:
		t.Fatalf("unsupported RequestMessage() received %q", received)
	default:
	}
}

func TestZeroValueWsConnSendMessageHonorsContext(t *testing.T) {
	var conn WsConn
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := conn.SendMessage(ctx, "192.0.2.22"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SendMessage() error = %v, want %v", err, context.DeadlineExceeded)
	}
	conn.Close()
}

var _ wsWire = (*blockingCloseWire)(nil)
