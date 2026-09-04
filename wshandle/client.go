package wshandle

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nxtrace/NTrace-core/pow"
	"github.com/nxtrace/NTrace-core/util"
)

func formatHostPort(addr, port string) string {
	clean := strings.TrimSpace(addr)
	clean = strings.Trim(clean, "[]")
	return net.JoinHostPort(clean, port)
}

type wsWriteJob struct {
	id         uint64
	generation uint64
	genDone    <-chan struct{}
	wire       wsWire
	kind       wsWriteKind
	msgType    int
	data       []byte
	requestIP  string
	requestCtx context.Context
	stopCancel func() bool
	awaitReply bool
	progress   *wsWriteProgress
	reply      chan<- string
	pongSerial uint64
}

type wsWriteProgress struct {
	began     atomic.Bool
	succeeded atomic.Bool
}

const (
	wsClientWriteQueueSize = 1024
	wsClientWriteTimeout   = 5 * time.Second
	wsClientDialTimeout    = 5 * time.Second
	wsClientPingInterval   = 54 * time.Second
	wsClientReconnectDelay = 200 * time.Millisecond
	wsClientDialRetryDelay = time.Second
)

type WsConn struct {
	Connecting       bool
	Connected        bool            // 连接状态
	MsgSendCh        chan string     // 消息发送通道
	MsgReceiveCh     chan string     // 消息接收通道
	Done             chan struct{}   // 发送结束通道
	Exit             chan bool       // 程序退出信号
	Interrupt        chan os.Signal  // 终端中止信号
	Conn             *websocket.Conn // 主连接
	ConnMux          sync.Mutex      // 连接互斥锁
	stateMu          sync.RWMutex
	closeOnce        sync.Once
	closeSignal      sync.Once
	receiveOnce      sync.Once
	closeCh          chan struct{} // signals background loops to exit
	baseCtx          context.Context
	rootCtx          context.Context
	cancelRoot       context.CancelCauseFunc
	managed          bool
	phase            wsPhase
	stateChanged     chan struct{}
	doneClosed       bool
	supervisorOnce   sync.Once
	supervisorReady  chan struct{}
	supervisorDone   chan struct{}
	firstAttemptDone chan struct{}
	firstAttemptOnce sync.Once
	firstAttemptErr  error
	submitCh         chan wsSubmission
	requestCancels   chan wsRequestCancel
	dialResults      chan wsDialResult
	readEvents       chan wsReadEvent
	managedWriteCh   chan wsWriteJob
	writeResults     chan wsWriteResult
	workerWG         sync.WaitGroup
	directIP         bool
	apiHost          string
	apiPort          string
	apiFastIP        string
	syncFirstAttempt bool
}

func (c *WsConn) ensureCompatSignalsLocked() {
	if c.stateChanged == nil {
		c.stateChanged = make(chan struct{})
	}
	if c.closeCh == nil {
		c.closeCh = make(chan struct{})
	}
	if c.rootCtx == nil {
		c.rootCtx, c.cancelRoot = context.WithCancelCause(context.Background())
	}
}

func (c *WsConn) notifyStateLocked() {
	if c.stateChanged == nil {
		c.stateChanged = make(chan struct{})
		return
	}
	close(c.stateChanged)
	c.stateChanged = make(chan struct{})
}

func (c *WsConn) stateSnapshot() (connected bool, phase wsPhase, changed <-chan struct{}, rootDone <-chan struct{}) {
	c.stateMu.Lock()
	c.ensureCompatSignalsLocked()
	connected = c.Connected
	phase = c.phase
	changed = c.stateChanged
	rootDone = c.rootCtx.Done()
	c.stateMu.Unlock()
	return
}

func (c *WsConn) closeSignalChan() {
	if c == nil {
		return
	}
	c.closeSignal.Do(func() {
		c.stateMu.Lock()
		c.ensureCompatSignalsLocked()
		ch := c.closeCh
		c.stateMu.Unlock()
		close(ch)
	})
}

func (c *WsConn) closeReceiveChannel() {
	c.receiveOnce.Do(func() {
		if c.MsgReceiveCh != nil {
			close(c.MsgReceiveCh)
		}
	})
}

func (c *WsConn) getDoneChan() chan struct{} {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.Done
}

func (c *WsConn) closeDoneLocked() {
	if c.Done != nil && !c.doneClosed {
		select {
		case <-c.Done:
		default:
			close(c.Done)
		}
		c.doneClosed = true
		c.notifyStateLocked()
	}
}

// ErrRequestResponseUnsupported reports that a compatibility WsConn has no
// supervisor capable of binding a response to its request generation.
var ErrRequestResponseUnsupported = errors.New("wshandle: request-bound responses require a managed connection")

var (
	errWriteQueueFull = errors.New("wshandle: write queue full")
	errConnClosed     = errors.New("wshandle: connection closed")
)

var wsconn *WsConn
var wsconnMu sync.RWMutex
var wsconnNewMu sync.Mutex
var envToken = util.EnvToken
var cacheTokenMu sync.Mutex
var cacheToken string
var createWsConnFn = createWsConn
var wsGetFastIPFn = util.GetFastIPWithContext
var wsGetTokenFn = pow.GetTokenWithContext

type wsEndpoint struct {
	host   string
	port   string
	fastIP string
	direct bool
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func isContextStop(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (c *WsConn) isClosed() bool {
	if c == nil {
		return true
	}
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

func (c *WsConn) baseContextErr() error {
	if c == nil {
		return nil
	}
	return contextErr(c.baseCtx)
}

func (c *WsConn) suppressCanceledContextLog(err error) bool {
	return isContextStop(err) || c.baseContextErr() != nil
}

func (c *WsConn) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		if c.managed {
			if c.cancelRoot != nil {
				c.cancelRoot(errConnClosed)
			}
			if c.Interrupt != nil {
				signal.Stop(c.Interrupt)
			}
			if c.supervisorDone != nil {
				<-c.supervisorDone
			}
			return
		}

		c.closeSignalChan()
		if c.cancelRoot != nil {
			c.cancelRoot(errConnClosed)
		}
		if c.Interrupt != nil {
			signal.Stop(c.Interrupt)
		}

		c.stateMu.Lock()
		conn := c.Conn
		c.Conn = nil
		c.Connected = false
		c.Connecting = false
		c.phase = wsPhaseClosed
		c.closeDoneLocked()
		c.notifyStateLocked()
		c.stateMu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		c.closeReceiveChannel()
	})
}

func (c *WsConn) setConnected(v bool) {
	c.stateMu.Lock()
	changed := c.Connected != v
	c.Connected = v
	if v {
		c.phase = wsPhaseConnected
	} else if c.phase == wsPhaseConnected {
		c.phase = wsPhaseIdle
	}
	if changed {
		c.notifyStateLocked()
	}
	c.stateMu.Unlock()
}

// SetConnected updates the websocket connection state under the internal lock.
func (c *WsConn) SetConnected(v bool) {
	if c == nil {
		return
	}
	c.setConnected(v)
}

func (c *WsConn) IsConnected() bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.Connected
}

func (c *WsConn) IsConnecting() bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.Connecting
}

func (c *WsConn) WaitUntilConnected(ctx context.Context) error {
	if c == nil {
		return errConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		connected, phase, changed, rootDone := c.stateSnapshot()
		if connected {
			return nil
		}
		if phase == wsPhaseClosed {
			return errConnClosed
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rootDone:
			return errConnClosed
		case <-c.closeCh:
			return errConnClosed
		case <-changed:
		}
	}
}

func apiServerErrorMessage(ip string) string {
	return `{"ip":"` + ip + `", "asnumber":"API Server Error"}`
}

func (c *WsConn) trySendReceiveMessage(msg string) {
	select {
	case c.MsgReceiveCh <- msg:
	case <-c.closeCh:
	default:
		log.Println("wshandle: dropping queued receive message")
	}
}

func initWsConnBase(ctx context.Context) (context.Context, chan os.Signal, wsEndpoint) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	ctx = normalizeContext(ctx)
	targetHost, targetPort := util.GetHostAndPort()
	endpoint := wsEndpoint{
		host: targetHost,
		port: targetPort,
	}
	if valid := net.ParseIP(targetHost); valid != nil {
		endpoint.direct = true
		endpoint.fastIP = targetHost
		endpoint.host = "api.nxtrace.org"
	}

	return ctx, interrupt, endpoint
}

func createWsConn(ctx context.Context) *WsConn {
	ctx, interrupt, endpoint := initWsConnBase(ctx)
	ws := newManagedWsConnWithPolicy(ctx, interrupt, endpoint, true)
	<-ws.firstAttemptDone
	if err := ws.firstAttemptFailure(); err != nil {
		ws.Close()
		panic(err)
	}
	return ws
}

func createWsConnAsync(ctx context.Context) *WsConn {
	ctx, interrupt, endpoint := initWsConnBase(ctx)
	return newManagedWsConn(ctx, interrupt, endpoint)
}

func replaceGlobalWsConn(newConn *WsConn, ctx context.Context) *WsConn {
	normalizedCtx := normalizeContext(ctx)
	wsconnMu.Lock()
	oldConn := wsconn
	if contextErr(normalizedCtx) != nil || (newConn != nil && newConn.isClosed()) {
		wsconnMu.Unlock()
		if newConn != nil && newConn != oldConn {
			newConn.Close()
		}
		return oldConn
	}
	wsconn = newConn
	wsconnMu.Unlock()

	if oldConn != nil && oldConn != newConn {
		oldConn.Close()
	}
	return newConn
}

func NewWithContext(ctx context.Context) *WsConn {
	wsconnNewMu.Lock()
	defer wsconnNewMu.Unlock()

	ctx = normalizeContext(ctx)
	newConn := createWsConnFn(ctx)
	return replaceGlobalWsConn(newConn, ctx)
}

func NewWithContextAsync(ctx context.Context) *WsConn {
	wsconnNewMu.Lock()
	defer wsconnNewMu.Unlock()
	ctx = normalizeContext(ctx)
	return replaceGlobalWsConn(createWsConnAsync(ctx), ctx)
}

func New() *WsConn {
	return NewWithContext(context.Background())
}

func NewAsync() *WsConn {
	return NewWithContextAsync(context.Background())
}

func GetWsConn() *WsConn {
	wsconnMu.RLock()
	defer wsconnMu.RUnlock()
	return wsconn
}
