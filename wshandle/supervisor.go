package wshandle

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nxtrace/NTrace-core/util"
)

const wsClientReceiveBacklog = 1024

type wsPhase uint8

const (
	wsPhaseIdle wsPhase = iota
	wsPhaseConnecting
	wsPhaseRetryWait
	wsPhaseConnected
	wsPhaseClosing
	wsPhaseClosed
)

type wsWire interface {
	ReadMessage() (int, []byte, error)
	SetWriteDeadline(time.Time) error
	WriteMessage(int, []byte) error
	Close() error
}

type wsWriteKind uint8

const (
	wsWriteRequest wsWriteKind = iota
	wsWritePing
	wsWriteClose
)

type wsDialStage uint8

const (
	wsDialStageFastIP wsDialStage = iota
	wsDialStageToken
	wsDialStageConnect
)

type wsDialRequest struct {
	URL        string
	Header     http.Header
	ServerName string
	Proxy      *url.URL
}

type wsDialResult struct {
	attemptID  uint64
	wire       wsWire
	publicConn *websocket.Conn
	fastIP     string
	stage      wsDialStage
	err        error
}

type wsReadEvent struct {
	generation uint64
	data       []byte
	err        error
}

type wsWriteResult struct {
	job wsWriteJob
	err error
}

type wsSubmission struct {
	ctx context.Context
	msg string
	ack chan error
}

type wsRequestCancel struct {
	generation uint64
	jobID      uint64
}

type wsGeneration struct {
	id         uint64
	ctx        context.Context
	cancel     context.CancelCauseFunc
	wire       wsWire
	publicConn *websocket.Conn
}

type wsSupervisorState struct {
	attemptID     uint64
	attemptActive bool
	attemptCancel context.CancelCauseFunc
	nextGenID     uint64
	nextJobID     uint64
	generation    *wsGeneration
	pending       map[uint64]wsWriteJob

	retryTimer     *time.Timer
	retryC         <-chan time.Time
	heartbeatTimer *time.Timer
	heartbeatC     <-chan time.Time
	graceTimer     *time.Timer
	graceC         <-chan time.Time

	pingPending     bool
	pingOutstanding bool
	pongSerial      uint64
	missedPongs     uint8
	interrupting    bool
}

var wsDialFn = defaultWSDial

var (
	errStaleWriteGeneration = errors.New("wshandle: stale write generation")
	errMissingWriteConn     = errors.New("wshandle: missing write connection")
	errRequestCanceled      = errors.New("wshandle: request canceled before write")
	errWebSocketRead        = errors.New("wshandle: websocket read failed")
	errWebSocketWrite       = errors.New("wshandle: websocket write failed")
	errPongTimeout          = errors.New("wshandle: pong timeout")
	errInterrupted          = errors.New("wshandle: interrupted")
)

func defaultWSDial(ctx context.Context, req wsDialRequest) (wsWire, *websocket.Conn, error) {
	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{ServerName: req.ServerName}
	if req.Proxy != nil {
		dialer.Proxy = http.ProxyURL(req.Proxy)
	}
	conn, _, err := dialer.DialContext(ctx, req.URL, req.Header)
	if conn == nil {
		return nil, nil, err
	}
	return conn, conn, err
}

func newManagedWsConn(ctx context.Context, interrupt chan os.Signal, endpoint wsEndpoint) *WsConn {
	return newManagedWsConnWithPolicy(ctx, interrupt, endpoint, false)
}

func newManagedWsConnWithPolicy(
	ctx context.Context,
	interrupt chan os.Signal,
	endpoint wsEndpoint,
	syncFirstAttempt bool,
) *WsConn {
	baseCtx := normalizeContext(ctx)
	rootCtx, cancelRoot := context.WithCancelCause(baseCtx)
	c := &WsConn{
		MsgSendCh:        make(chan string, 10),
		MsgReceiveCh:     make(chan string, 10),
		Done:             make(chan struct{}),
		Interrupt:        interrupt,
		closeCh:          make(chan struct{}),
		baseCtx:          baseCtx,
		rootCtx:          rootCtx,
		cancelRoot:       cancelRoot,
		managed:          true,
		phase:            wsPhaseIdle,
		stateChanged:     make(chan struct{}),
		supervisorReady:  make(chan struct{}),
		supervisorDone:   make(chan struct{}),
		firstAttemptDone: make(chan struct{}),
		submitCh:         make(chan wsSubmission),
		requestCancels:   make(chan wsRequestCancel, wsClientWriteQueueSize),
		dialResults:      make(chan wsDialResult),
		readEvents:       make(chan wsReadEvent, wsClientReceiveBacklog),
		managedWriteCh:   make(chan wsWriteJob, wsClientWriteQueueSize),
		writeResults:     make(chan wsWriteResult, wsClientWriteQueueSize),
		directIP:         endpoint.direct,
		apiHost:          endpoint.host,
		apiPort:          endpoint.port,
		apiFastIP:        endpoint.fastIP,
		syncFirstAttempt: syncFirstAttempt,
	}
	c.startManagedSupervisor()
	return c
}

func (c *WsConn) startManagedSupervisor() {
	c.supervisorOnce.Do(func() {
		c.workerWG.Add(1)
		go c.managedWriteLoop()
		go c.supervise()
	})
	<-c.supervisorReady
}

func (c *WsConn) completeFirstAttempt() {
	c.firstAttemptOnce.Do(func() {
		close(c.firstAttemptDone)
	})
}

func (c *WsConn) supervise() {
	state := wsSupervisorState{pending: make(map[uint64]wsWriteJob)}
	var receiveQueue []string
	defer c.finishSupervision(&state)

	if c.rootCtx.Err() == nil {
		c.beginDialAttempt(&state)
	}
	close(c.supervisorReady)

	sendCh := c.MsgSendCh
	interruptCh := c.Interrupt
	for {
		var receiveOut chan string
		var receiveMsg string
		var readEvents <-chan wsReadEvent
		if len(receiveQueue) > 0 && c.MsgReceiveCh != nil {
			receiveOut = c.MsgReceiveCh
			receiveMsg = receiveQueue[0]
		}
		if len(receiveQueue) < wsClientReceiveBacklog {
			readEvents = c.readEvents
		}
		select {
		case <-c.rootCtx.Done():
			return
		case receiveOut <- receiveMsg:
			receiveQueue[0] = ""
			receiveQueue = receiveQueue[1:]
		case result := <-c.dialResults:
			c.handleDialResult(&state, result)
		case event := <-readEvents:
			c.handleReadEvent(&state, event, &receiveQueue)
		case result := <-c.writeResults:
			c.handleWriteResult(&state, result)
		case submission := <-c.submitCh:
			c.handleSubmission(&state, submission)
		case canceled := <-c.requestCancels:
			c.handleRequestCancel(&state, canceled)
		case <-state.retryC:
			stopSupervisorTimer(&state.retryTimer, &state.retryC)
			c.beginDialAttempt(&state)
		case <-state.heartbeatC:
			stopSupervisorTimer(&state.heartbeatTimer, &state.heartbeatC)
			c.handleHeartbeat(&state)
		case <-state.graceC:
			stopSupervisorTimer(&state.graceTimer, &state.graceC)
			c.cancelRoot(errInterrupted)
		case msg, ok := <-sendCh:
			if !ok {
				sendCh = nil
				continue
			}
			c.handlePublicWrite(&state, msg)
		case <-interruptCh:
			interruptCh = nil
			c.handleInterruptEvent(&state)
		}
	}
}

func (c *WsConn) beginDialAttempt(state *wsSupervisorState) {
	if state.attemptActive || state.generation != nil || c.rootCtx.Err() != nil {
		return
	}
	state.attemptID++
	state.attemptActive = true
	attemptCtx, cancel := context.WithCancelCause(c.rootCtx)
	state.attemptCancel = cancel
	c.publishManagedPhase(wsPhaseConnecting)

	attemptID := state.attemptID
	c.workerWG.Add(1)
	go func() {
		defer c.workerWG.Done()
		result := c.performDialAttempt(attemptCtx, attemptID)
		if c.rootCtx.Err() != nil {
			closeDialResult(result)
			return
		}
		select {
		case c.dialResults <- result:
		case <-c.rootCtx.Done():
			closeDialResult(result)
		}
	}()
}

func (c *WsConn) performDialAttempt(ctx context.Context, attemptID uint64) wsDialResult {
	direct, host, port, fastIP := c.endpointSnapshot()
	result := wsDialResult{attemptID: attemptID, fastIP: fastIP}
	if !direct && host != "" && net.ParseIP(host) == nil {
		refreshed, err := wsGetFastIPFn(ctx, host, port, true)
		if err != nil {
			result.stage = wsDialStageFastIP
			result.err = err
			return result
		}
		fastIP = refreshed
		result.fastIP = refreshed
	}

	allowCachedToken := !c.syncFirstAttempt || attemptID > 1
	token, ua, err := websocketCredentials(ctx, fastIP, host, port, allowCachedToken)
	if err != nil {
		result.stage = wsDialStageToken
		result.err = err
		return result
	}

	dialURL := url.URL{Scheme: "wss", Host: formatHostPort(fastIP, port), Path: "/v3/ipGeoWs"}
	request := wsDialRequest{
		URL:        dialURL.String(),
		ServerName: host,
		Proxy:      util.GetProxy(),
		Header: http.Header{
			"Host":          []string{host},
			"User-Agent":    ua,
			"Authorization": []string{"Bearer " + token},
		},
	}
	dialCtx, cancel := context.WithTimeout(ctx, wsClientDialTimeout)
	wire, publicConn, err := wsDialFn(dialCtx, request)
	cancel()
	result.stage = wsDialStageConnect
	result.wire = wire
	result.publicConn = publicConn
	result.err = err
	if ctx.Err() != nil {
		closeDialResult(result)
		result.wire = nil
		result.publicConn = nil
		result.err = ctx.Err()
	}
	return result
}

func websocketCredentials(
	ctx context.Context,
	fastIP, host, port string,
	allowCachedToken bool,
) (string, []string, error) {
	if envToken != "" {
		return envToken, []string{"Privileged Client"}, nil
	}
	if allowCachedToken {
		if token := loadCachedToken(); token != "" {
			return token, []string{util.UserAgent}, nil
		}
	}
	tokenHost := fastIP
	tokenDomain := host
	if provider := util.GetPowProvider(); provider != "" {
		tokenHost = provider
		tokenDomain = provider
	}
	token, err := wsGetTokenFn(ctx, tokenHost, tokenDomain, port)
	if err != nil {
		return "", nil, err
	}
	storeCachedToken(token)
	return token, []string{util.UserAgent}, nil
}

func loadCachedToken() string {
	cacheTokenMu.Lock()
	defer cacheTokenMu.Unlock()
	return cacheToken
}

func storeCachedToken(token string) {
	cacheTokenMu.Lock()
	cacheToken = token
	cacheTokenMu.Unlock()
}

func (c *WsConn) endpointSnapshot() (direct bool, host, port, fastIP string) {
	c.stateMu.RLock()
	direct = c.directIP
	host = c.apiHost
	port = c.apiPort
	fastIP = c.apiFastIP
	c.stateMu.RUnlock()
	return
}

func (c *WsConn) handleDialResult(state *wsSupervisorState, result wsDialResult) {
	if result.attemptID != state.attemptID || !state.attemptActive || c.rootCtx.Err() != nil {
		closeDialResult(result)
		return
	}
	state.attemptActive = false
	if state.attemptCancel != nil {
		state.attemptCancel(nil)
		state.attemptCancel = nil
	}
	if result.err != nil {
		closeDialResult(result)
		if util.EnvDevMode && c.shouldPanicDialFailure(result) && !isContextStop(result.err) {
			if c.syncFirstAttempt && result.attemptID == 1 {
				c.recordFirstAttemptFailure(result.err)
				c.cancelRoot(result.err)
				c.completeFirstAttempt()
				return
			}
			panic(result.err)
		}
		c.logDialFailure(result)
		delay := wsClientReconnectDelay
		if result.stage == wsDialStageConnect && result.attemptID > 1 {
			delay = wsClientDialRetryDelay
		}
		c.publishManagedPhase(wsPhaseRetryWait)
		resetSupervisorTimer(&state.retryTimer, &state.retryC, delay)
		c.completeFirstAttempt()
		return
	}

	c.stateMu.Lock()
	c.apiFastIP = result.fastIP
	c.stateMu.Unlock()
	c.installGeneration(state, result)
	c.completeFirstAttempt()
}

func (c *WsConn) shouldPanicDialFailure(result wsDialResult) bool {
	switch result.stage {
	case wsDialStageFastIP:
		return c.syncFirstAttempt && result.attemptID == 1
	case wsDialStageToken:
		return true
	default:
		return false
	}
}

func (c *WsConn) recordFirstAttemptFailure(err error) {
	c.stateMu.Lock()
	c.firstAttemptErr = err
	c.phase = wsPhaseClosing
	c.Connected = false
	c.Connecting = false
	c.notifyStateLocked()
	c.stateMu.Unlock()
}

func (c *WsConn) firstAttemptFailure() error {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.firstAttemptErr
}

func (c *WsConn) logDialFailure(result wsDialResult) {
	if c.suppressCanceledContextLog(result.err) {
		return
	}
	switch result.stage {
	case wsDialStageFastIP:
		if c.syncFirstAttempt && result.attemptID == 1 {
			log.Printf("fast ip probe failed: %v", result.err)
		} else {
			log.Printf("fast ip refresh failed: %v", result.err)
		}
	case wsDialStageToken:
		log.Printf("pow token fetch failed: %v", result.err)
	case wsDialStageConnect:
		log.Printf("dial: %v", result.err)
	}
}

func (c *WsConn) installGeneration(state *wsSupervisorState, result wsDialResult) {
	state.nextGenID++
	genCtx, cancel := context.WithCancelCause(c.rootCtx)
	generation := &wsGeneration{
		id:         state.nextGenID,
		ctx:        genCtx,
		cancel:     cancel,
		wire:       result.wire,
		publicConn: result.publicConn,
	}
	state.generation = generation
	state.missedPongs = 0
	state.pongSerial = 0
	state.pingPending = false
	state.pingOutstanding = false
	state.interrupting = false
	stopSupervisorTimer(&state.retryTimer, &state.retryC)
	c.publishManagedConnected(result.publicConn)
	c.startManagedReader(generation)
	resetSupervisorTimer(&state.heartbeatTimer, &state.heartbeatC, wsClientPingInterval)
}

func (c *WsConn) startManagedReader(generation *wsGeneration) {
	c.workerWG.Add(1)
	go func() {
		defer c.workerWG.Done()
		for {
			_, data, err := generation.wire.ReadMessage()
			event := wsReadEvent{generation: generation.id, data: data, err: err}
			select {
			case c.readEvents <- event:
			case <-generation.ctx.Done():
				return
			case <-c.rootCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
}

func (c *WsConn) managedWriteLoop() {
	defer c.workerWG.Done()
	for {
		if c.rootCtx.Err() != nil {
			return
		}
		select {
		case <-c.rootCtx.Done():
			return
		case job := <-c.managedWriteCh:
			result := wsWriteResult{job: job}
			if job.awaitReply && contextErr(job.requestCtx) != nil {
				result.err = errRequestCanceled
			} else {
				select {
				case <-job.genDone:
					result.err = errStaleWriteGeneration
				default:
					if job.wire == nil {
						result.err = errMissingWriteConn
					} else {
						_ = job.wire.SetWriteDeadline(time.Now().Add(wsClientWriteTimeout))
						if job.awaitReply && contextErr(job.requestCtx) != nil {
							result.err = errRequestCanceled
						} else {
							result.err = job.wire.WriteMessage(job.msgType, job.data)
						}
					}
				}
			}
			select {
			case c.writeResults <- result:
			case <-c.rootCtx.Done():
				return
			}
		}
	}
}

func (c *WsConn) handleReadEvent(state *wsSupervisorState, event wsReadEvent, receiveQueue *[]string) {
	if state.generation == nil || event.generation != state.generation.id {
		return
	}
	if event.err != nil {
		if state.interrupting {
			c.cancelRoot(errInterrupted)
			return
		}
		c.endGeneration(state, errors.Join(errWebSocketRead, event.err), true)
		return
	}
	if string(event.data) == "pong" {
		state.pongSerial++
		state.missedPongs = 0
		state.pingOutstanding = false
		return
	}
	c.completePendingResponse(state, event.generation, event.data)
	*receiveQueue = append(*receiveQueue, string(event.data))
}

func (c *WsConn) completePendingResponse(state *wsSupervisorState, generation uint64, data []byte) {
	var response struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(data, &response); err != nil || response.IP == "" {
		return
	}

	var oldestID uint64
	for id, job := range state.pending {
		if job.generation != generation || job.requestIP != response.IP {
			continue
		}
		if oldestID == 0 || id < oldestID {
			oldestID = id
		}
	}
	if oldestID != 0 {
		c.finishPendingRequest(state, oldestID)
	}
}

func (c *WsConn) handlePublicWrite(state *wsSupervisorState, msg string) {
	if err := c.registerRequest(state, msg, nil, false); err != nil {
		c.trySendReceiveMessage(apiServerErrorMessage(msg))
		if errors.Is(err, errWriteQueueFull) {
			c.endGeneration(state, err, true)
		}
	}
}

func (c *WsConn) handleSubmission(state *wsSupervisorState, submission wsSubmission) {
	if err := contextErr(submission.ctx); err != nil {
		submission.ack <- err
		return
	}
	err := c.registerRequest(state, submission.msg, submission.ctx, true)
	if errors.Is(err, errWriteQueueFull) {
		c.endGeneration(state, err, true)
	}
	submission.ack <- err
}

func (c *WsConn) registerRequest(
	state *wsSupervisorState,
	msg string,
	requestCtx context.Context,
	awaitReply bool,
) error {
	if awaitReply {
		if err := contextErr(requestCtx); err != nil {
			return err
		}
	}
	if c.rootCtx.Err() != nil || state.generation == nil || state.interrupting {
		return errConnClosed
	}
	state.nextJobID++
	job := wsWriteJob{
		id:         state.nextJobID,
		generation: state.generation.id,
		genDone:    state.generation.ctx.Done(),
		wire:       state.generation.wire,
		kind:       wsWriteRequest,
		msgType:    websocket.TextMessage,
		data:       []byte(msg),
		requestIP:  msg,
		requestCtx: requestCtx,
		awaitReply: awaitReply,
	}
	if !c.enqueueManagedWrite(job) {
		return errWriteQueueFull
	}
	if awaitReply {
		c.watchRequestContext(&job)
	}
	state.pending[job.id] = job
	return nil
}

func (c *WsConn) watchRequestContext(job *wsWriteJob) {
	c.workerWG.Add(1)
	canceled := wsRequestCancel{generation: job.generation, jobID: job.id}
	job.stopCancel = context.AfterFunc(job.requestCtx, func() {
		defer c.workerWG.Done()
		select {
		case c.requestCancels <- canceled:
		case <-c.rootCtx.Done():
		}
	})
}

func (c *WsConn) handleRequestCancel(state *wsSupervisorState, canceled wsRequestCancel) {
	job, ok := state.pending[canceled.jobID]
	if !ok || job.generation != canceled.generation {
		return
	}
	c.finishPendingRequest(state, canceled.jobID)
}

func (c *WsConn) finishPendingRequest(state *wsSupervisorState, jobID uint64) (wsWriteJob, bool) {
	job, ok := state.pending[jobID]
	if !ok {
		return wsWriteJob{}, false
	}
	delete(state.pending, jobID)
	if job.stopCancel != nil && job.stopCancel() {
		c.workerWG.Done()
	}
	return job, true
}

// SendMessage submits msg to the current websocket generation.
func (c *WsConn) SendMessage(ctx context.Context, msg string) error {
	if c == nil {
		return errConnClosed
	}
	ctx = normalizeContext(ctx)
	if err := contextErr(ctx); err != nil {
		return err
	}
	if !c.managed {
		_, phase, _, rootDone := c.stateSnapshot()
		if phase == wsPhaseClosed {
			return errConnClosed
		}
		select {
		case c.MsgSendCh <- msg:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-rootDone:
			return errConnClosed
		}
	}

	submission := wsSubmission{
		ctx: ctx,
		msg: msg,
		ack: make(chan error, 1),
	}
	select {
	case c.submitCh <- submission:
		return <-submission.ack
	case <-ctx.Done():
		return ctx.Err()
	case <-c.rootCtx.Done():
		return errConnClosed
	}
}

func (c *WsConn) enqueueManagedWrite(job wsWriteJob) bool {
	select {
	case c.managedWriteCh <- job:
		return true
	case <-c.rootCtx.Done():
		return false
	default:
		return false
	}
}

func (c *WsConn) handleWriteResult(state *wsSupervisorState, result wsWriteResult) {
	job := result.job
	if job.kind == wsWriteRequest {
		pendingJob, pending := state.pending[job.id]
		if errors.Is(result.err, errRequestCanceled) {
			if pending {
				c.finishPendingRequest(state, job.id)
			}
			return
		}
		if result.err == nil {
			if pending && !pendingJob.awaitReply {
				c.finishPendingRequest(state, job.id)
			}
			return
		}
		if pending {
			c.finishPendingRequest(state, job.id)
			if contextErr(pendingJob.requestCtx) == nil {
				c.trySendReceiveMessage(apiServerErrorMessage(pendingJob.requestIP))
			}
		}
		if state.generation != nil && job.generation == state.generation.id {
			c.endGeneration(state, errors.Join(errWebSocketWrite, result.err), true)
		}
		return
	}
	if state.generation == nil || job.generation != state.generation.id {
		return
	}
	if result.err != nil {
		if state.interrupting {
			c.cancelRoot(errInterrupted)
			return
		}
		c.endGeneration(state, errors.Join(errWebSocketWrite, result.err), true)
		return
	}
	switch job.kind {
	case wsWritePing:
		state.pingPending = false
		state.pingOutstanding = job.pongSerial == state.pongSerial
		resetSupervisorTimer(&state.heartbeatTimer, &state.heartbeatC, wsClientPingInterval)
	case wsWriteClose:
		// Wait for the peer/read loop or the interrupt grace timer.
	}
}

func (c *WsConn) handleHeartbeat(state *wsSupervisorState) {
	if state.generation == nil || state.interrupting {
		return
	}
	if state.pingOutstanding {
		state.missedPongs++
		state.pingOutstanding = false
		if state.missedPongs >= 2 {
			c.endGeneration(state, errPongTimeout, true)
			return
		}
	}
	state.nextJobID++
	job := wsWriteJob{
		id:         state.nextJobID,
		generation: state.generation.id,
		genDone:    state.generation.ctx.Done(),
		wire:       state.generation.wire,
		kind:       wsWritePing,
		msgType:    websocket.TextMessage,
		data:       []byte("ping"),
		pongSerial: state.pongSerial,
	}
	state.pingPending = true
	if !c.enqueueManagedWrite(job) {
		state.pingPending = false
		c.endGeneration(state, errWriteQueueFull, true)
	}
}

func (c *WsConn) handleInterruptEvent(state *wsSupervisorState) {
	if state.interrupting {
		return
	}
	if state.generation == nil {
		c.cancelRoot(errInterrupted)
		return
	}
	state.interrupting = true
	state.nextJobID++
	job := wsWriteJob{
		id:         state.nextJobID,
		generation: state.generation.id,
		genDone:    state.generation.ctx.Done(),
		wire:       state.generation.wire,
		kind:       wsWriteClose,
		msgType:    websocket.CloseMessage,
		data:       websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
	}
	if !c.enqueueManagedWrite(job) {
		c.cancelRoot(errInterrupted)
		return
	}
	resetSupervisorTimer(&state.graceTimer, &state.graceC, time.Second)
}

func (c *WsConn) endGeneration(state *wsSupervisorState, cause error, retry bool) {
	generation := state.generation
	if generation == nil {
		return
	}
	state.generation = nil
	generation.cancel(cause)
	stopSupervisorTimer(&state.heartbeatTimer, &state.heartbeatC)
	stopSupervisorTimer(&state.graceTimer, &state.graceC)
	state.pingPending = false
	state.pingOutstanding = false
	state.interrupting = false
	c.publishManagedDisconnected(retry)
	_ = generation.wire.Close()
	c.failPendingGeneration(state, generation.id)
	if retry && c.rootCtx.Err() == nil {
		resetSupervisorTimer(&state.retryTimer, &state.retryC, wsClientReconnectDelay)
	}
}

func (c *WsConn) failPendingGeneration(state *wsSupervisorState, generation uint64) {
	for id, job := range state.pending {
		if job.generation != generation {
			continue
		}
		c.finishPendingRequest(state, id)
		if contextErr(job.requestCtx) == nil {
			c.trySendReceiveMessage(apiServerErrorMessage(job.requestIP))
		}
	}
}

func (c *WsConn) publishManagedPhase(phase wsPhase) {
	c.stateMu.Lock()
	c.phase = phase
	c.Connected = phase == wsPhaseConnected
	c.Connecting = phase == wsPhaseConnecting
	c.notifyStateLocked()
	c.stateMu.Unlock()
}

func (c *WsConn) publishManagedConnected(conn *websocket.Conn) {
	c.stateMu.Lock()
	if c.Done == nil || c.doneClosed {
		c.Done = make(chan struct{})
		c.doneClosed = false
	}
	c.Conn = conn
	c.phase = wsPhaseConnected
	c.Connected = true
	c.Connecting = false
	c.notifyStateLocked()
	c.stateMu.Unlock()
}

func (c *WsConn) publishManagedDisconnected(retry bool) {
	c.stateMu.Lock()
	c.Conn = nil
	c.Connected = false
	c.Connecting = false
	if retry {
		c.phase = wsPhaseRetryWait
	} else {
		c.phase = wsPhaseClosing
	}
	c.closeDoneLocked()
	c.notifyStateLocked()
	c.stateMu.Unlock()
}

func (c *WsConn) finishSupervision(state *wsSupervisorState) {
	if state.attemptCancel != nil {
		state.attemptCancel(errConnClosed)
	}
	stopSupervisorTimer(&state.retryTimer, &state.retryC)
	stopSupervisorTimer(&state.heartbeatTimer, &state.heartbeatC)
	stopSupervisorTimer(&state.graceTimer, &state.graceC)
	if state.generation != nil {
		c.endGeneration(state, context.Cause(c.rootCtx), false)
	}
	c.completeFirstAttempt()
	c.closeSignalChan()
	c.workerWG.Wait()
	if c.Interrupt != nil {
		signal.Stop(c.Interrupt)
	}
	c.stateMu.Lock()
	c.Conn = nil
	c.Connected = false
	c.Connecting = false
	c.phase = wsPhaseClosed
	c.closeDoneLocked()
	c.notifyStateLocked()
	c.stateMu.Unlock()
	c.closeReceiveChannel()
	close(c.supervisorDone)
}

func closeDialResult(result wsDialResult) {
	publicWire, _ := result.wire.(*websocket.Conn)
	if result.wire != nil {
		_ = result.wire.Close()
	}
	if result.publicConn != nil && result.publicConn != publicWire {
		_ = result.publicConn.Close()
	}
}

func resetSupervisorTimer(timer **time.Timer, timerC *<-chan time.Time, delay time.Duration) {
	if *timer == nil {
		*timer = time.NewTimer(delay)
	} else {
		if !(*timer).Stop() {
			select {
			case <-(*timer).C:
			default:
			}
		}
		(*timer).Reset(delay)
	}
	*timerC = (*timer).C
}

func stopSupervisorTimer(timer **time.Timer, timerC *<-chan time.Time) {
	if *timer != nil {
		if !(*timer).Stop() {
			select {
			case <-(*timer).C:
			default:
			}
		}
	}
	*timerC = nil
}
