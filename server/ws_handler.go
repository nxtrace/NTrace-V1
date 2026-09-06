package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/nxtrace/NTrace-core/internal/service"
	"github.com/nxtrace/NTrace-core/trace"
)

var traceUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return browserOriginAllowed(r)
	},
}

const (
	wsSendQueueSize = 1024
	wsWriteTimeout  = 5 * time.Second
)

var (
	errWSSlowConsumer     = errors.New("websocket client too slow for mtr stream")
	errWSSessionClosed    = errors.New("websocket session closed")
	errWSSessionFinished  = errors.New("websocket session finished")
	errWSTraceWorkerPanic = errors.New("websocket trace worker panic")
	traceTracerouteFn     = trace.Traceroute
	traceRunMTRRawFn      = trace.RunMTRRaw
)

// sanitizeLogParam 清理用户输入中的换行和控制字符，防止日志注入。
func sanitizeLogParam(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			b.WriteString("\\n")
		} else if r < 0x20 && r != '\t' {
			// 保留 tab，替换其他 C0 控制字符
			b.WriteRune('\uFFFD')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func newWSSessionContext(parent context.Context) (context.Context, context.CancelCauseFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithCancelCause(parent)
}

type wsEnvelope struct {
	Type   string      `json:"type"`
	Data   interface{} `json:"data,omitempty"`
	Error  string      `json:"error,omitempty"`
	Status int         `json:"status,omitempty"`
}

type wsConn interface {
	WriteJSON(v interface{}) error
	SetWriteDeadline(t time.Time) error
	WriteControl(messageType int, data []byte, deadline time.Time) error
	Close() error
	NextReader() (messageType int, r io.Reader, err error)
}

type wsInitConn interface {
	SetReadDeadline(t time.Time) error
	SetReadLimit(limit int64)
	ReadMessage() (messageType int, p []byte, err error)
}

type traceWSConn interface {
	wsConn
	wsInitConn
}

type wsSessionState uint8

const (
	wsSessionOpen wsSessionState = iota
	wsSessionDraining
	wsSessionAborting
	wsSessionClosed
)

type wsSessionCloseRequest struct {
	code   int
	reason string
}

type wsTraceSession struct {
	conn         wsConn
	ctx          context.Context
	cancel       context.CancelCauseFunc
	stateMu      sync.Mutex
	state        wsSessionState
	sendCh       chan wsEnvelope
	workers      sync.WaitGroup
	closed       atomic.Bool
	closeRequest wsSessionCloseRequest
	lang         string
	seen         map[int]int
}

func newWSTraceSession(parent context.Context, conn wsConn, lang string, queueSize int) *wsTraceSession {
	if queueSize <= 0 {
		queueSize = wsSendQueueSize
	}
	ctx, cancel := newWSSessionContext(parent)
	s := &wsTraceSession{
		conn:   conn,
		ctx:    ctx,
		cancel: cancel,
		sendCh: make(chan wsEnvelope, queueSize),
		lang:   lang,
		seen:   make(map[int]int),
	}
	s.workers.Go(s.writeLoop)
	s.workers.Go(s.readLoop)
	return s
}

func readWSInitMessage(conn wsInitConn) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	conn.SetReadLimit(maxWSInitMessageBytes)
	_, message, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return message, nil
}

func (s *wsTraceSession) writeLoop() {
	for {
		select {
		case <-s.ctx.Done():
			s.requestAbort(context.Cause(s.ctx), 0, "")
			s.finishAbort()
			return
		case msg, ok := <-s.sendCh:
			if !ok {
				if !s.finishDrain() {
					s.finishAbort()
				}
				return
			}
			if !s.writeAllowed() {
				s.requestAbort(context.Cause(s.ctx), 0, "")
				s.finishAbort()
				return
			}
			deadline := time.Now().Add(wsWriteTimeout)
			_ = s.conn.SetWriteDeadline(deadline)
			err := s.conn.WriteJSON(msg)
			if err != nil {
				s.requestAbort(err, websocket.CloseInternalServerErr, "write failed")
				s.finishAbort()
				return
			}
		}
	}
}

func (s *wsTraceSession) readLoop() {
	for {
		if _, _, err := s.conn.NextReader(); err != nil {
			if s.ctx.Err() != nil {
				s.requestAbort(context.Cause(s.ctx), 0, "")
			} else {
				s.requestAbort(err, websocket.CloseNormalClosure, "client disconnected")
			}
			return
		}
	}
}

func (s *wsTraceSession) send(msg wsEnvelope) error {
	s.stateMu.Lock()
	if s.state != wsSessionOpen || s.ctx.Err() != nil {
		s.stateMu.Unlock()
		return errWSSessionClosed
	}
	select {
	case s.sendCh <- msg:
		s.stateMu.Unlock()
		return nil
	default:
		s.stateMu.Unlock()
		s.requestAbort(errWSSlowConsumer, websocket.CloseTryAgainLater, "client too slow for mtr stream")
		return errWSSlowConsumer
	}
}

func (s *wsTraceSession) closeWithCode(code int, reason string) {
	s.requestAbort(errWSSessionClosed, code, reason)
}

func (s *wsTraceSession) finish() {
	s.requestDrain()
	s.workers.Wait()
}

func (s *wsTraceSession) runTrace(run func(context.Context)) {
	done := make(chan struct{})
	s.workers.Go(func() {
		defer close(done)
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("[deploy] websocket trace worker panic: %v", recovered)
				s.requestAbort(errWSTraceWorkerPanic, websocket.CloseInternalServerErr, "internal error")
			}
		}()
		run(s.ctx)
	})
	<-done
}

func (s *wsTraceSession) requestDrain() {
	s.stateMu.Lock()
	if s.state != wsSessionOpen {
		s.stateMu.Unlock()
		return
	}
	if s.ctx.Err() != nil {
		s.stateMu.Unlock()
		s.requestAbort(context.Cause(s.ctx), 0, "")
		return
	}
	s.state = wsSessionDraining
	s.closed.Store(true)
	close(s.sendCh)
	s.stateMu.Unlock()
}

func (s *wsTraceSession) requestAbort(cause error, code int, reason string) {
	if cause == nil {
		cause = errWSSessionClosed
	}

	s.stateMu.Lock()
	if s.state == wsSessionAborting || s.state == wsSessionClosed {
		s.stateMu.Unlock()
		return
	}
	if s.ctx.Err() != nil {
		cause = context.Cause(s.ctx)
		code = 0
		reason = ""
	}
	s.state = wsSessionAborting
	s.closeRequest = wsSessionCloseRequest{code: code, reason: reason}
	s.closed.Store(true)
	s.stateMu.Unlock()
	s.cancel(cause)
}

func (s *wsTraceSession) writeAllowed() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return (s.state == wsSessionOpen || s.state == wsSessionDraining) && s.ctx.Err() == nil
}

func (s *wsTraceSession) finishDrain() bool {
	if s.ctx.Err() != nil {
		s.requestAbort(context.Cause(s.ctx), 0, "")
		return false
	}

	s.stateMu.Lock()
	if s.state != wsSessionDraining || s.ctx.Err() != nil {
		s.stateMu.Unlock()
		if s.ctx.Err() != nil {
			s.requestAbort(context.Cause(s.ctx), 0, "")
		}
		return false
	}
	s.state = wsSessionClosed
	s.stateMu.Unlock()

	s.cancel(errWSSessionFinished)
	_ = s.conn.Close()
	return true
}

func (s *wsTraceSession) finishAbort() {
	s.stateMu.Lock()
	if s.state == wsSessionClosed {
		s.stateMu.Unlock()
		return
	}
	if s.state != wsSessionAborting {
		s.state = wsSessionAborting
		s.closeRequest = wsSessionCloseRequest{}
		s.closed.Store(true)
	}
	closeRequest := s.closeRequest
	s.state = wsSessionClosed
	s.stateMu.Unlock()

	if closeRequest.code != 0 {
		deadline := time.Now().Add(wsWriteTimeout)
		_ = s.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(closeRequest.code, closeRequest.reason),
			deadline,
		)
	}
	_ = s.conn.Close()
}

func traceWebsocketHandler(c *gin.Context) {
	conn, err := traceUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[deploy] websocket upgrade failed: %v", err)
		return
	}
	serveTraceWebsocket(c.Request.Context(), conn)
}

func serveTraceWebsocket(parent context.Context, conn traceWSConn) {
	message, err := readWSInitMessage(conn)
	if err != nil {
		log.Printf("[deploy] websocket read failed: %v", err)
		_ = conn.Close()
		return
	}

	session := newWSTraceSession(parent, conn, "", wsSendQueueSize)
	defer session.finish()

	req, err := decodeWSInitRequest(message)
	if err != nil {
		_ = session.send(wsEnvelope{Type: "error", Error: "invalid request payload", Status: 400})
		return
	}

	setup, statusCode, err := prepareWebsocketTrace(session.ctx, req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if statusCode == 0 {
			statusCode = 500
		}
		log.Printf("[deploy] websocket prepare trace failed target=%s error=%v", sanitizeLogParam(req.Target), err)
		_ = session.send(wsEnvelope{Type: "error", Error: err.Error(), Status: statusCode})
		return
	}

	session.lang = setup.Config.Lang

	startPayload := gin.H{
		"target":        setup.Target,
		"resolved_ip":   setup.IP.String(),
		"protocol":      setup.Protocol,
		"data_provider": setup.DataProvider,
		"language":      setup.Config.Lang,
	}
	if err := session.send(wsEnvelope{Type: "start", Data: startPayload}); err != nil {
		log.Printf("[deploy] websocket send start failed: %v", err)
		return
	}

	log.Printf("[deploy] (ws) trace request target=%s proto=%s provider=%s lang=%s ipv4_only=%t ipv6_only=%t", sanitizeLogParam(setup.Target), sanitizeLogParam(setup.Protocol), sanitizeLogParam(setup.DataProvider), sanitizeLogParam(setup.Config.Lang), setup.Req.IPv4Only, setup.Req.IPv6Only)
	log.Printf("[deploy] (ws) target resolved target=%s ip=%s via dot=%s", sanitizeLogParam(setup.Target), setup.IP, sanitizeLogParam(strings.ToLower(setup.Req.DotServer)))

	mode := setup.Req.Mode
	if mode == "" {
		mode = "single"
	}

	session.runTrace(func(sessionCtx context.Context) {
		switch mode {
		case "mtr", "continuous":
			runMTRTrace(sessionCtx, session, setup)
		default:
			runSingleTrace(sessionCtx, session, setup)
		}
	})
}

func decodeWSInitRequest(message []byte) (traceRequest, error) {
	var req traceRequest
	err := json.Unmarshal(message, &req)
	return req, err
}

func prepareWebsocketTrace(ctx context.Context, req traceRequest) (*traceExecution, int, error) {
	// Only the WebSocket dispatcher executes these modes. REST always runs a
	// normal trace, even when a client sends mode=mtr.
	switch strings.ToLower(strings.TrimSpace(req.Mode)) {
	case "mtr", "continuous":
		req.Queries = 1
		req.MaxAttempts = 1
	}
	return prepareTrace(ctx, req)
}

func runSingleTrace(ctx context.Context, session *wsTraceSession, setup *traceExecution) {
	session.seen = make(map[int]int)

	res, duration, err := executeTrace(ctx, session, setup, func(cfg *trace.Config) {
		cfg.RealtimePrinter = nil
		cfg.AsyncPrinter = func(result *trace.Result) {
			for idx, attempts := range result.Hops {
				if len(attempts) == 0 {
					continue
				}
				snapshot := append([]trace.Hop(nil), attempts...)
				newLen := len(snapshot)
				if newLen == 0 {
					continue
				}
				if prevLen, ok := session.seen[idx]; ok && newLen <= prevLen {
					continue
				}
				session.seen[idx] = newLen

				hop := buildHopResponse(snapshot, idx, session.lang)
				if len(hop.Attempts) == 0 {
					continue
				}
				if err := session.send(wsEnvelope{Type: "hop", Data: hop}); err != nil {
					log.Printf("[deploy] websocket hop send failed ttl=%d err=%v", hop.TTL, err)
					return
				}
			}
		}
	})

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		log.Printf("[deploy] websocket trace failed target=%s error=%v", sanitizeLogParam(setup.Target), err)
		_ = session.send(wsEnvelope{Type: "error", Error: err.Error(), Status: 500})
		return
	}

	if session.closed.Load() {
		return
	}

	traceMapURL := traceMapURLForResult(setup, res)
	if traceMapURL != "" {
		log.Printf("[deploy] (ws) trace map generated target=%s url=%s", sanitizeLogParam(setup.Target), traceMapURL)
	}

	final := traceResponse{
		Target:       setup.Target,
		ResolvedIP:   setup.IP.String(),
		Protocol:     setup.Protocol,
		DataProvider: setup.DataProvider,
		TraceMapURL:  traceMapURL,
		Language:     setup.Config.Lang,
		Hops:         convertHops(res, setup.Config.Lang),
		DurationMs:   duration.Milliseconds(),
		StopReason:   service.NewTraceStopReason(res.StopReason),
	}

	if err := session.send(wsEnvelope{Type: "complete", Data: final}); err != nil {
		log.Printf("[deploy] websocket send complete failed: %v", err)
	}
	log.Printf("[deploy] (ws) trace completed target=%s hops=%d duration=%s", sanitizeLogParam(setup.Target), len(final.Hops), duration)
}

func runMTRTrace(parentCtx context.Context, session *wsTraceSession, setup *traceExecution) {
	hopInterval := resolveWebMTRHopInterval(setup.Req)
	maxPerHop := setup.Req.MaxRounds // 0 = unlimited

	iteration := 0
	var pathEnd *service.TraceStopReason
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	err := executeMTRRaw(ctx, session, setup, trace.MTRRawOptions{
		HopInterval: hopInterval,
		MaxPerHop:   maxPerHop,
		OnPathEnd: func(reason *trace.StopReason) {
			pathEnd = service.NewTraceStopReason(reason)
			if err := session.send(wsEnvelope{Type: "path_end", Data: pathEnd}); err != nil {
				cancel()
			}
		},
	}, func(rec trace.MTRRawRecord) {
		if rec.Iteration > iteration {
			iteration = rec.Iteration
		}
		if err := session.send(wsEnvelope{Type: "mtr_raw", Data: rec}); err != nil {
			cancel()
		}
	})
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		log.Printf("[deploy] websocket MTR raw trace failed target=%s error=%v", sanitizeLogParam(setup.Target), err)
		_ = session.send(wsEnvelope{Type: "error", Error: err.Error(), Status: 500})
		return
	}

	if !session.closed.Load() {
		_ = session.send(wsEnvelope{Type: "complete", Data: gin.H{"iteration": iteration, "path_end": pathEnd}})
	}
}

func executeMTRRaw(ctx context.Context, session *wsTraceSession, setup *traceExecution, opts trace.MTRRawOptions, onRecord trace.MTRRawOnRecord) error {
	config := setup.Config

	if session.closed.Load() {
		return nil
	}

	if opts.HopInterval > 0 {
		// Per-hop scheduling only needs NextTrace API/FastIP setup now; the trace runtime
		// itself no longer depends on per-session mutable globals.
		log.Printf("[deploy] (ws) starting MTR per-hop trace target=%s resolved=%s method=%s lang=%s maxHops=%d hopInterval=%s maxPerHop=%d",
			sanitizeLogParam(setup.Target), setup.IP.String(), string(setup.Method), sanitizeLogParam(config.Lang), config.MaxHops, opts.HopInterval, opts.MaxPerHop)

		traceMu.Lock()
		_, err := withTraceSetupContext(setup, func() (struct{}, error) {
			if setup.NeedsNextTraceAPIV3 {
				ensureNextTraceAPIV3ConnectionFn()
			}
			return struct{}{}, nil
		})
		traceMu.Unlock()
		if err != nil {
			return err
		}

		return traceRunMTRRawFn(ctx, setup.Method, config, opts, onRecord)
	}

	// Legacy round-based path: inject RunRound with per-round locking.
	log.Printf("[deploy] (ws) starting MTR round-based trace target=%s resolved=%s method=%s lang=%s maxHops=%d interval=%s maxRounds=%d",
		sanitizeLogParam(setup.Target), setup.IP.String(), string(setup.Method), sanitizeLogParam(config.Lang), config.MaxHops, opts.Interval, opts.MaxRounds)

	opts.RunRound = func(method trace.Method, cfg trace.Config) (*trace.Result, error) {
		traceMu.Lock()
		defer traceMu.Unlock()

		return withTraceSetupContext(setup, func() (*trace.Result, error) {
			if setup.NeedsNextTraceAPIV3 {
				ensureNextTraceAPIV3ConnectionFn()
			}
			return traceTracerouteFn(method, cfg)
		})
	}

	return traceRunMTRRawFn(ctx, setup.Method, config, opts, onRecord)
}

func executeTrace(ctx context.Context, session *wsTraceSession, setup *traceExecution, configure func(*trace.Config)) (*trace.Result, time.Duration, error) {
	traceMu.Lock()
	defer traceMu.Unlock()

	config := setup.Config
	config.Context = ctx
	if configure != nil {
		configure(&config)
	}

	if session.closed.Load() {
		return nil, 0, nil
	}

	log.Printf("[deploy] (ws) starting trace target=%s resolved=%s method=%s lang=%s queries=%d maxHops=%d", sanitizeLogParam(setup.Target), setup.IP.String(), string(setup.Method), sanitizeLogParam(config.Lang), config.NumMeasurements, config.MaxHops)
	start := time.Now()
	res, err := withTraceSetupContext(setup, func() (*trace.Result, error) {
		if setup.NeedsNextTraceAPIV3 {
			ensureNextTraceAPIV3ConnectionFn()
		}
		return traceTracerouteFn(setup.Method, config)
	})
	duration := time.Since(start)
	return res, duration, err
}

func resolveWebMTRHopInterval(req traceRequest) time.Duration {
	if req.HopIntervalMs > 0 {
		return time.Duration(req.HopIntervalMs) * time.Millisecond
	}
	if req.IntervalMs > 0 {
		return time.Duration(req.IntervalMs) * time.Millisecond
	}
	return time.Second
}
