package trace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace/internal"
	"github.com/nxtrace/NTrace-core/util"
)

var (
	errHopLimitTimeout    = errors.New("hop timeout")
	errInvalidMethod      = errors.New("invalid method")
	errNaturalDone        = errors.New("trace natural done")
	errTracerouteExecuted = errors.New("traceroute already executed")
	geoCache              = sync.Map{}
	ipGeoSF               singleflight.Group
)

type Config struct {
	Context          context.Context
	OSType           int
	ICMPMode         int
	SrcAddr          string
	SrcPort          int
	SourceDevice     string
	BeginHop         int
	MaxHops          int
	NumMeasurements  int
	MaxAttempts      int
	ParallelRequests int
	Timeout          time.Duration
	DstIP            net.IP
	DstPort          int
	Quic             bool
	IPGeoSource      ipgeo.Source
	GeoLookupOffset  int
	RDNS             bool
	AlwaysWaitRDNS   bool
	PacketInterval   int
	TTLInterval      int
	Lang             string
	DN42             bool
	RealtimePrinter  func(res *Result, ttl int)
	AsyncPrinter     func(res *Result)
	PktSize          int
	RandomPacketSize bool
	TOS              int
	Maptrace         bool
	DisableMPLS      bool
}

type Method string

const (
	ICMPTrace Method = "icmp"
	UDPTrace  Method = "udp"
	TCPTrace  Method = "tcp"
)

type attemptKey struct {
	ttl int
	i   int
}

type attemptPort struct {
	srcPort int
	i       int
}

type sentInfo struct {
	ttl         int
	i           int
	srcPort     int
	payloadSize int
	start       time.Time
}

type matchTask struct {
	srcPort  int
	seq      int
	ack      int
	peer     net.Addr
	finish   time.Time
	mpls     []string
	response probeResponse
}

type probeResponseKind uint8

const (
	probeResponseUnknown probeResponseKind = iota
	probeResponseTransit
	probeResponseDestination
	probeResponseUnreachable
)

type probeResponse struct {
	kind        probeResponseKind
	detail      string
	marker      string
	responderIP string
}

func probeResponseFromICMP(response internal.ICMPResponse) probeResponse {
	return probeResponseFromICMPForMethod(response, ICMPTrace)
}

func probeResponseFromICMPForMethod(response internal.ICMPResponse, method Method) probeResponse {
	switch response.Kind {
	case internal.ICMPResponseTransit:
		return probeResponse{kind: probeResponseTransit, detail: response.Description}
	case internal.ICMPResponseEchoReply:
		return probeResponse{kind: probeResponseDestination, detail: response.Description}
	case internal.ICMPResponsePortUnreachable:
		if method == UDPTrace {
			return probeResponse{kind: probeResponseDestination, detail: response.Description, marker: response.Marker}
		}
		return probeResponse{kind: probeResponseUnreachable, detail: response.Description, marker: response.Marker}
	case internal.ICMPResponseUnreachable:
		return probeResponse{kind: probeResponseUnreachable, detail: response.Description, marker: response.Marker}
	default:
		return probeResponse{}
	}
}

func probeResponseFromTCPAck(ack int) probeResponse {
	detail := "TCP SYN/ACK"
	if ack != 0 {
		detail = "TCP RST"
	}
	return probeResponse{kind: probeResponseDestination, detail: detail}
}

func lowerTraceFinal(final *atomic.Int32, ttl int) {
	if final == nil || ttl <= 0 {
		return
	}
	for {
		old := final.Load()
		if old != -1 && ttl >= int(old) {
			return
		}
		if final.CompareAndSwap(old, int32(ttl)) {
			return
		}
	}
}

func markDestinationFinal(final *atomic.Int32, ttl int, response probeResponse) {
	if response.kind == probeResponseDestination {
		lowerTraceFinal(final, ttl)
	}
}

type Tracer interface {
	Execute() (*Result, error)
}

func applyTracerouteDefaults(config *Config) {
	if config == nil {
		return
	}
	if config.MaxHops == 0 {
		config.MaxHops = 30
	}
	if config.NumMeasurements == 0 {
		config.NumMeasurements = 3
	}
	if config.ParallelRequests == 0 {
		config.ParallelRequests = config.NumMeasurements * 5
	}
}

func waitForTraceDelay(ctx context.Context, d time.Duration) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer stopAndDrainTimer(timer)
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx == nil || ctx.Err() == nil
	}
}

func retryTraceProbeLookup(ctx context.Context, lookup func() bool) bool {
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if lookup() {
		return true
	}
	if !waitForTraceDelay(ctx, 10*time.Millisecond) {
		return false
	}
	return lookup()
}

func stopAndDrainTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func acquireTraceSemaphore(ctx context.Context, sem *semaphore.Weighted) error {
	if sem == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return sem.Acquire(ctx, 1)
}

func normalizeICMPMode(config *Config) {
	if config == nil {
		return
	}
	if config.ICMPMode <= 0 && util.EnvICMPMode > 0 {
		config.ICMPMode = util.EnvICMPMode
	}
	switch config.ICMPMode {
	case 0, 1, 2:
	default:
		config.ICMPMode = 0
	}
}

func deriveMaxAttempts(config *Config) {
	if config == nil {
		return
	}
	if config.MaxAttempts <= 0 && util.EnvMaxAttempts > 0 {
		config.MaxAttempts = util.EnvMaxAttempts
	}
	if config.MaxAttempts > 0 && config.MaxAttempts >= config.NumMeasurements {
		return
	}

	n := config.NumMeasurements
	switch {
	case n <= 2 || n >= 10:
		config.MaxAttempts = n
	case n <= 6:
		config.MaxAttempts = n + 3
	default:
		config.MaxAttempts = 10
	}
}

func selectTracer(method Method, config Config) (Tracer, error) {
	isIPv4 := config.DstIP.To4() != nil
	switch method {
	case ICMPTrace:
		if isIPv4 {
			return &ICMPTracer{Config: config}, nil
		}
		return &ICMPTracerv6{Config: config}, nil
	case UDPTrace:
		if isIPv4 {
			return &UDPTracer{Config: config}, nil
		}
		return &UDPTracerIPv6{Config: config}, nil
	case TCPTrace:
		if isIPv4 {
			return &TCPTracer{Config: config}, nil
		}
		return &TCPTracerIPv6{Config: config}, nil
	default:
		return nil, errInvalidMethod
	}
}

func waitForPendingGeoData(ctx context.Context, result *Result) {
	if result == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		result.geoWG.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctxDoneChan(ctx):
	case <-time.After(30 * time.Second):
	}
	result.geoCanceled.Store(true)
	result.markAllPendingGeoTimeout()
}

func ctxDoneChan(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

func Traceroute(method Method, config Config) (*Result, error) {
	normalizeRuntimeConfig(&config)
	applyTracerouteDefaults(&config)
	normalizeICMPMode(&config)
	deriveMaxAttempts(&config)

	tracer, err := selectTracer(method, config)
	if err != nil {
		return &Result{}, err
	}

	result, err := tracer.Execute()
	if err != nil && errors.Is(err, syscall.EPERM) {
		err = fmt.Errorf("%w，请使用 root 权限运行", err)
	}
	waitForPendingGeoData(config.Context, result)
	return result, err
}

func TracerouteWithContext(ctx context.Context, method Method, config Config) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	config.Context = ctx
	return Traceroute(method, config)
}

func normalizeRuntimeConfig(config *Config) {
	if config == nil {
		return
	}
	if config.SourceDevice == "" && util.SrcDev != "" {
		config.SourceDevice = util.SrcDev
	}
}

type Result struct {
	Hops        [][]Hop
	StopReason  *StopReason `json:",omitempty"`
	lock        sync.RWMutex
	tailDone    []bool
	responses   map[int][]probeResponse
	attempts    map[int]*traceTTLAttempts
	provisional map[int]int
	TraceMapUrl string
	geoWait     time.Duration
	geoWG       sync.WaitGroup
	geoCanceled atomic.Bool
}

// StopReason describes why a finite traceroute stopped.
type StopReason struct {
	Hop int `json:"hop"`
	// Reason is one of the StopReason constants.
	Reason string `json:"reason"`
	// Responses contains sorted, deduplicated human-readable response
	// descriptions and responder addresses when available.
	Responses []string `json:"responses,omitempty"`
	// Markers contains sorted, deduplicated machine-readable ICMP marker values.
	Markers []string `json:"markers,omitempty"`
}

type traceTTLAttempts struct {
	launched   map[int]struct{}
	settled    map[int]struct{}
	launchDone bool
}

const (
	StopReasonDestination = "destination_reached"
	StopReasonUnreachable = "unreachable"
	StopReasonMaxHops     = "max_hops"
)

const PendingGeoSource = "pending"
const timeoutGeoSource = "timeout"

func isPendingGeo(geo *ipgeo.IPGeoData) bool {
	return geo != nil && geo.Source == PendingGeoSource
}

func pendingGeo() *ipgeo.IPGeoData {
	return &ipgeo.IPGeoData{Source: PendingGeoSource}
}

func timeoutGeo() *ipgeo.IPGeoData {
	return &ipgeo.IPGeoData{
		Country:   "网络故障",
		CountryEn: "Network Error",
		Source:    timeoutGeoSource,
	}
}

func geoWaitForMeasurements(numMeasurements int) time.Duration {
	if numMeasurements <= 0 {
		numMeasurements = 1
	}
	maxRetries := numMeasurements - 1
	if maxRetries > 5 {
		maxRetries = 5
	}

	total := 0
	for attempt := 0; attempt <= maxRetries; attempt++ {
		timeout := 2 + attempt
		if timeout > 6 {
			timeout = 6
		}
		total += timeout
	}
	return time.Duration(total) * time.Second
}

// 判定 Hop 是否“有效”
func isValidHop(h Hop) bool {
	return h.Success && h.Address != nil
}

func (s *Result) addLocked(hop Hop, attemptIdx, numMeasurements, maxAttempts int) (bool, int) {
	k := hop.TTL - 1
	if k < 0 || k >= len(s.Hops) {
		return false, -1
	}
	bucket := s.Hops[k]
	n := numMeasurements
	if n <= 0 {
		n = 1
	}

	switch {
	case attemptIdx < n-1:
		// attemptIdx < N-1：无条件放行
		s.Hops[k] = append(bucket, hop)
		return true, len(s.Hops[k]) - 1
	case attemptIdx >= n-1:
		// 正在决定第 N 条：审计
		// 放行条件（三选一）：
		// (1) 前 N-1 中已存在有效值
		// (2) 当前 hop 为有效值
		// (3) 已到最后一次尝试
		if len(bucket) >= n {
			return false, -1
		}

		if s.tailDone[k] {
			return false, -1
		}

		hasValid := false
		for _, h := range bucket {
			if isValidHop(h) {
				hasValid = true
				break
			}
		}
		if hasValid || isValidHop(hop) || attemptIdx >= maxAttempts-1 {
			s.Hops[k] = append(bucket, hop) // 填满第 N 个
			s.tailDone[k] = true
			return true, len(s.Hops[k]) - 1
		}
		// 否则丢弃，等待后续更优候选（长度仍保持 N-1）
		return false, -1
	}
	return false, -1
}

func (s *Result) add(hop Hop, attemptIdx, numMeasurements, maxAttempts int) (bool, int) {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.addLocked(hop, attemptIdx, numMeasurements, maxAttempts)
}

func (s *Result) ttlAttemptsLocked(ttl int) *traceTTLAttempts {
	if s.attempts == nil {
		s.attempts = make(map[int]*traceTTLAttempts)
	}
	state := s.attempts[ttl]
	if state == nil {
		state = &traceTTLAttempts{
			launched: make(map[int]struct{}),
			settled:  make(map[int]struct{}),
		}
		s.attempts[ttl] = state
	}
	return state
}

func (s *Result) markAttemptLaunched(ttl, attemptIdx int, final *atomic.Int32) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	if traceTTLAboveFinal(final, ttl) {
		return false
	}
	s.ttlAttemptsLocked(ttl).launched[attemptIdx] = struct{}{}
	return true
}

func (s *Result) markTTLLaunchDone(ttl int) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.ttlAttemptsLocked(ttl).launchDone = true
}

func (s *Result) markTTLLaunchDoneAndCommit(ctx context.Context, ttl, numMeasurements int, final *atomic.Int32) {
	s.lock.Lock()
	defer s.lock.Unlock()
	state := s.ttlAttemptsLocked(ttl)
	state.launchDone = true
	if ctx != nil && ctx.Err() != nil {
		return
	}
	s.lowerStableResponseFinalLocked(ttl, numMeasurements, final)
}

func (s *Result) ttlDisplayComplete(ttl, numMeasurements int) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	if ttl <= 0 || ttl > len(s.Hops) {
		return false
	}
	if numMeasurements <= 0 {
		numMeasurements = 1
	}
	return len(s.Hops[ttl-1]) >= numMeasurements
}

func (s *Result) ttlStableLocked(ttl, numMeasurements int) bool {
	if ttl <= 0 || ttl > len(s.Hops) {
		return false
	}
	state := s.attempts[ttl]
	if state == nil || !state.launchDone || len(state.launched) != len(state.settled) {
		return false
	}
	if numMeasurements <= 0 {
		numMeasurements = 1
	}
	return len(s.Hops[ttl-1]) >= numMeasurements
}

func (s *Result) ttlStable(ttl, numMeasurements int) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.ttlStableLocked(ttl, numMeasurements)
}

func traceTTLAboveFinal(final *atomic.Int32, ttl int) bool {
	if final == nil {
		return false
	}
	known := final.Load()
	return known > 0 && ttl > int(known)
}

func (s *Result) markAttemptSettledLocked(ttl, attemptIdx int) {
	state := s.ttlAttemptsLocked(ttl)
	if _, launched := state.launched[attemptIdx]; launched {
		state.settled[attemptIdx] = struct{}{}
	}
}

func (s *Result) lowerStableResponseFinalLocked(ttl, numMeasurements int, final *atomic.Int32) {
	if !s.ttlStableLocked(ttl, numMeasurements) {
		return
	}

	hasTransit := false
	hasDestination := false
	hasUnreachable := false
	for _, response := range s.responses[ttl] {
		switch response.kind {
		case probeResponseTransit:
			hasTransit = true
		case probeResponseDestination:
			hasDestination = true
		case probeResponseUnreachable:
			hasUnreachable = true
		}
	}
	if hasDestination || (!hasTransit && hasUnreachable) {
		lowerTraceFinal(final, ttl)
	}
}

func (s *Result) setGeoWait(numMeasurements int) {
	s.geoWait = geoWaitForMeasurements(numMeasurements)
}

func (s *Result) reduce(final int) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if final > 0 && final < len(s.Hops) {
		s.Hops = s.Hops[:final]
	}
}

func (s *Result) recordResponse(ttl int, response probeResponse) {
	if ttl <= 0 || response.kind == probeResponseUnknown {
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	if s.responses == nil {
		s.responses = make(map[int][]probeResponse)
	}
	s.responses[ttl] = append(s.responses[ttl], response)
}

func (s *Result) stopAfterTTL(ttl, maxHops int) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.stopAfterTTLLocked(ttl, maxHops)
}

func (s *Result) stopAfterTTLLocked(ttl, maxHops int) bool {
	if ttl <= 0 || ttl > len(s.Hops) {
		return false
	}

	hasTransit := false
	hasDestination := false
	hasUnreachable := false
	destinationMarkers := make(map[string]struct{})
	unreachableMarkers := make(map[string]struct{})
	destinationDetails := make(map[string]struct{})
	unreachableDetails := make(map[string]struct{})
	for _, response := range s.responses[ttl] {
		switch response.kind {
		case probeResponseTransit:
			hasTransit = true
		case probeResponseDestination:
			hasDestination = true
			addResponseDetail(destinationDetails, response)
			if response.marker != "" {
				destinationMarkers[response.marker] = struct{}{}
			}
		case probeResponseUnreachable:
			hasUnreachable = true
			addResponseDetail(unreachableDetails, response)
			if response.marker != "" {
				unreachableMarkers[response.marker] = struct{}{}
			}
		}
	}

	switch {
	case hasDestination:
		s.StopReason = &StopReason{
			Hop:       ttl,
			Reason:    StopReasonDestination,
			Responses: sortedResponseDetails(destinationDetails),
			Markers:   sortedResponseDetails(destinationMarkers),
		}
		return true
	case hasTransit && ttl < maxHops:
		return false
	case !hasTransit && hasUnreachable:
		s.StopReason = &StopReason{
			Hop:       ttl,
			Reason:    StopReasonUnreachable,
			Responses: sortedResponseDetails(unreachableDetails),
			Markers:   sortedResponseDetails(unreachableMarkers),
		}
		return true
	case ttl >= maxHops:
		s.StopReason = &StopReason{Hop: ttl, Reason: StopReasonMaxHops}
		return true
	default:
		return false
	}
}

func (s *Result) stopAfterStableTTL(ttl, maxHops, numMeasurements int, final *atomic.Int32) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	if final != nil {
		known := int(final.Load())
		if known > 0 && known < ttl {
			ttl = known
		}
	}
	if !s.ttlStableLocked(ttl, numMeasurements) || !s.stopAfterTTLLocked(ttl, maxHops) {
		return false
	}
	lowerTraceFinal(final, ttl)
	return true
}

func (s *Result) stableFinalAtOrBefore(cursor, maxHops, numMeasurements int, final *atomic.Int32) bool {
	if final == nil {
		return false
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	known := int(final.Load())
	if known <= 0 || known > cursor || !s.ttlStableLocked(known, numMeasurements) || !s.stopAfterTTLLocked(known, maxHops) {
		return false
	}
	lowerTraceFinal(final, known)
	return true
}

func (s *Result) snapshotThroughTTL(ttl int) *Result {
	s.lock.RLock()
	defer s.lock.RUnlock()

	snapshot := &Result{
		Hops:        make([][]Hop, len(s.Hops)),
		TraceMapUrl: s.TraceMapUrl,
		responses:   make(map[int][]probeResponse),
	}
	if ttl > len(s.Hops) {
		ttl = len(s.Hops)
	}
	for ttlIdx := 0; ttlIdx < ttl; ttlIdx++ {
		snapshot.Hops[ttlIdx] = make([]Hop, len(s.Hops[ttlIdx]))
		for i, hop := range s.Hops[ttlIdx] {
			if hop.Geo != nil {
				geo := *hop.Geo
				hop.Geo = &geo
			}
			hop.MPLS = append([]string(nil), hop.MPLS...)
			snapshot.Hops[ttlIdx][i] = hop
		}
	}
	for responseTTL, responses := range s.responses {
		if responseTTL <= ttl {
			snapshot.responses[responseTTL] = append([]probeResponse(nil), responses...)
		}
	}
	if s.StopReason != nil {
		reason := *s.StopReason
		reason.Responses = append([]string(nil), reason.Responses...)
		reason.Markers = append([]string(nil), reason.Markers...)
		snapshot.StopReason = &reason
	}
	return snapshot
}

func advanceStableTracePrint(
	ctx context.Context,
	res *Result,
	cursor, maxHops, numMeasurements int,
	final *atomic.Int32,
	asyncPrinter func(*Result),
	realtimePrinter func(*Result, int),
) (nextCursor int, stop bool) {
	if res == nil || (ctx != nil && ctx.Err() != nil) {
		return cursor, false
	}
	if res.stableFinalAtOrBefore(cursor, maxHops, numMeasurements, final) {
		return cursor, true
	}

	nextTTL := cursor + 1
	if !res.ttlStable(nextTTL, numMeasurements) {
		return cursor, false
	}

	stop = res.stopAfterStableTTL(nextTTL, maxHops, numMeasurements, final)
	if asyncPrinter != nil {
		asyncPrinter(res.snapshotThroughTTL(nextTTL))
	}
	if realtimePrinter != nil {
		res.waitGeo(ctx, nextTTL-1)
		if ctx != nil && ctx.Err() != nil {
			return cursor, false
		}
		realtimePrinter(res.snapshotThroughTTL(nextTTL), nextTTL-1)
	}
	return nextTTL, stop
}

func addResponseDetail(details map[string]struct{}, response probeResponse) {
	if response.detail == "" {
		return
	}
	details[response.detail] = struct{}{}
}

func sortedResponseDetails(details map[string]struct{}) []string {
	result := make([]string, 0, len(details))
	for detail := range details {
		result = append(result, detail)
	}
	sort.Strings(result)
	return result
}

type Hop struct {
	Success  bool
	Address  net.Addr
	Hostname string
	TTL      int
	RTT      time.Duration
	Error    error
	Geo      *ipgeo.IPGeoData
	Lang     string
	MPLS     []string
}

func isLDHASCII(label string) bool {
	for i := 0; i < len(label); i++ {
		b := label[i]
		if b > 0x7F {
			return false
		}
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' {
			continue
		}
		return false
	}
	return true
}

func CanonicalHostname(s string) string {
	if s == "" {
		return ""
	}
	// 去掉尾点
	s = strings.TrimSuffix(s, ".")
	// 按标签逐个处理，确保仅对需要的标签做 IDNA 转换
	parts := strings.Split(s, ".")
	for i, label := range parts {
		if label == "" {
			continue
		}
		if isLDHASCII(label) {
			// 纯 ASCII 且仅含 LDH：保留原大小写，不做大小写折叠
			continue
		}
		// 含非 ASCII 或不满足 LDH：对该标签做 IDNA 转 ASCII
		if ascii, err := idna.Lookup.ToASCII(label); err == nil && ascii != "" {
			parts[i] = ascii
		}
		// 若转换失败，保留原标签
	}
	return strings.Join(parts, ".")
}

func (s *Result) updateHop(ttl, idx int, updated Hop) {
	s.lock.Lock()
	defer s.lock.Unlock()

	k := ttl - 1
	if k < 0 || k >= len(s.Hops) {
		return
	}
	if idx < 0 || idx >= len(s.Hops[k]) {
		return
	}

	h := &s.Hops[k][idx]
	if h.Address == nil || updated.Address == nil || h.Address.String() != updated.Address.String() {
		return
	}
	if updated.Hostname != "" {
		h.Hostname = updated.Hostname
	}
	if updated.Geo != nil {
		h.Geo = updated.Geo
	}
	if updated.Lang != "" {
		h.Lang = updated.Lang
	}
}

func (s *Result) waitGeo(ctx context.Context, ttlIdx int) {
	if s.geoWait <= 0 {
		return
	}
	if ttlIdx < 0 {
		return
	}

	deadline := time.Now().Add(s.geoWait)
	for {
		if !s.hasPendingGeo(ttlIdx) {
			return
		}
		if time.Now().After(deadline) {
			s.markPendingGeoTimeout(ttlIdx)
			return
		}
		if ctx == nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		select {
		case <-ctx.Done():
			s.markPendingGeoTimeout(ttlIdx)
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (s *Result) hasPendingGeo(ttlIdx int) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if ttlIdx < 0 || ttlIdx >= len(s.Hops) {
		return false
	}

	for _, hop := range s.Hops[ttlIdx] {
		if hop.Address == nil {
			continue
		}
		if isPendingGeo(hop.Geo) {
			return true
		}
	}
	return false
}

func (s *Result) markPendingGeoTimeout(ttlIdx int) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if ttlIdx < 0 || ttlIdx >= len(s.Hops) {
		return
	}

	for i := range s.Hops[ttlIdx] {
		hop := &s.Hops[ttlIdx][i]
		if hop.Address == nil || !isPendingGeo(hop.Geo) {
			continue
		}
		hop.Geo = timeoutGeo()
	}
}

func (s *Result) markAllPendingGeoTimeout() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for ttlIdx := range s.Hops {
		for i := range s.Hops[ttlIdx] {
			hop := &s.Hops[ttlIdx][i]
			if hop.Address == nil || !isPendingGeo(hop.Geo) {
				continue
			}
			hop.Geo = timeoutGeo()
		}
	}
}

func (s *Result) addMatchedHop(hop Hop, response probeResponse, final *atomic.Int32, attemptIdx, numMeasurements, maxAttempts int, cfg Config) bool {
	needsMetadata := cfg.IPGeoSource != nil || cfg.RDNS
	prepareHopMetadata(&hop, cfg)

	s.lock.Lock()
	if s.attemptSettledLocked(hop.TTL, attemptIdx) {
		s.lock.Unlock()
		return false
	}
	if traceTTLAboveFinal(final, hop.TTL) {
		s.markAttemptSettledLocked(hop.TTL, attemptIdx)
		s.lock.Unlock()
		return false
	}
	if response.kind != probeResponseUnknown {
		if s.responses == nil {
			s.responses = make(map[int][]probeResponse)
		}
		response = responseWithPeer(response, hop.Address)
		s.responses[hop.TTL] = append(s.responses[hop.TTL], response)
	}
	markDestinationFinal(final, hop.TTL, response)
	added, idx := s.addLocked(hop, attemptIdx, numMeasurements, maxAttempts)
	if !added {
		idx = s.promoteWinningResponseLocked(hop, response, numMeasurements)
		added = idx >= 0
	}
	s.markAttemptSettledLocked(hop.TTL, attemptIdx)
	s.lowerStableResponseFinalLocked(hop.TTL, numMeasurements, final)
	s.lock.Unlock()

	if added && needsMetadata {
		s.launchHopMetadata(hop, idx, cfg)
	}
	return added
}

func (s *Result) addWithGeoAsync(hop Hop, attemptIdx, numMeasurements, maxAttempts int, cfg Config) {
	needsMetadata := cfg.IPGeoSource != nil || cfg.RDNS
	prepareHopMetadata(&hop, cfg)

	added, idx := s.add(hop, attemptIdx, numMeasurements, maxAttempts)
	if !added {
		return
	}
	if !needsMetadata {
		return
	}

	s.launchHopMetadata(hop, idx, cfg)
}

func prepareHopMetadata(hop *Hop, cfg Config) {
	if cfg.IPGeoSource != nil && hop.Geo == nil {
		hop.Geo = pendingGeo()
	} else if cfg.IPGeoSource != nil && hop.Geo.Source == "" {
		hop.Geo.Source = PendingGeoSource
	}
	if hop.Lang == "" {
		hop.Lang = cfg.Lang
	}
}

func (s *Result) launchHopMetadata(hop Hop, idx int, cfg Config) {
	s.geoWG.Add(1)
	go func(ttl, idx int, h Hop) {
		defer s.geoWG.Done()
		_ = h.fetchIPData(cfg)
		if !s.geoCanceled.Load() {
			s.updateHop(ttl, idx, h)
		}
	}(hop.TTL, idx, hop)
}

func isTerminalResponse(response probeResponse) bool {
	return response.kind == probeResponseDestination || response.kind == probeResponseUnreachable
}

func responseWithPeer(response probeResponse, peer net.Addr) probeResponse {
	if peer == nil {
		return response
	}
	peerIP := util.AddrIP(peer)
	if peerIP == nil {
		return response
	}
	response.responderIP = peerIP.String()
	if !isTerminalResponse(response) {
		return response
	}
	if response.detail == "" {
		response.detail = response.responderIP
	} else {
		response.detail += " from " + response.responderIP
	}
	return response
}

func (s *Result) promoteWinningResponseLocked(hop Hop, response probeResponse, numMeasurements int) int {
	k := hop.TTL - 1
	if k < 0 || k >= len(s.Hops) || len(s.Hops[k]) == 0 {
		return -1
	}
	if idx, ok := s.provisional[hop.TTL]; ok {
		switch response.kind {
		case probeResponseDestination, probeResponseTransit:
			if idx >= 0 && idx < len(s.Hops[k]) {
				s.Hops[k][idx] = hop
				delete(s.provisional, hop.TTL)
				return idx
			}
		case probeResponseUnreachable:
			return -1
		}
	}
	if response.kind != probeResponseDestination &&
		(response.kind != probeResponseUnreachable || !s.unreachableWinsLocked(hop.TTL)) {
		return -1
	}
	limit := numMeasurements
	if limit <= 0 || limit > len(s.Hops[k]) {
		limit = len(s.Hops[k])
	}
	for i := limit - 1; i >= 0; i-- {
		if !isValidHop(s.Hops[k][i]) {
			s.Hops[k][i] = hop
			if response.kind == probeResponseUnreachable {
				s.rememberProvisionalLocked(hop.TTL, i)
			}
			return i
		}
	}
	s.Hops[k][limit-1] = hop
	if response.kind == probeResponseUnreachable {
		s.rememberProvisionalLocked(hop.TTL, limit-1)
	}
	return limit - 1
}

func (s *Result) rememberProvisionalLocked(ttl, idx int) {
	if s.provisional == nil {
		s.provisional = make(map[int]int)
	}
	s.provisional[ttl] = idx
}

func (s *Result) unreachableWinsLocked(ttl int) bool {
	hasUnreachable := false
	for _, response := range s.responses[ttl] {
		switch response.kind {
		case probeResponseDestination, probeResponseTransit:
			return false
		case probeResponseUnreachable:
			hasUnreachable = true
		}
	}
	return hasUnreachable
}

func (s *Result) addTimeout(hop Hop, final *atomic.Int32, attemptIdx, numMeasurements, maxAttempts int) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.attemptSettledLocked(hop.TTL, attemptIdx) {
		return false
	}
	if traceTTLAboveFinal(final, hop.TTL) {
		s.markAttemptSettledLocked(hop.TTL, attemptIdx)
		return false
	}
	added, _ := s.addLocked(hop, attemptIdx, numMeasurements, maxAttempts)
	s.markAttemptSettledLocked(hop.TTL, attemptIdx)
	s.lowerStableResponseFinalLocked(hop.TTL, numMeasurements, final)
	return added
}

func (s *Result) addFailedAttempt(hop Hop, final *atomic.Int32, attemptIdx, numMeasurements, maxAttempts int) bool {
	return s.addTimeout(hop, final, attemptIdx, numMeasurements, maxAttempts)
}

func (s *Result) attemptSettledLocked(ttl, attemptIdx int) bool {
	state := s.attempts[ttl]
	if state == nil {
		return false
	}
	_, settled := state.settled[attemptIdx]
	return settled
}

func (s *Result) settleAttempt(ttl, attemptIdx int) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.markAttemptSettledLocked(ttl, attemptIdx)
}

func (s *Result) settleAttemptAndCommit(ctx context.Context, ttl, attemptIdx, numMeasurements int, final *atomic.Int32) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.markAttemptSettledLocked(ttl, attemptIdx)
	if ctx != nil && ctx.Err() != nil {
		return
	}
	s.lowerStableResponseFinalLocked(ttl, numMeasurements, final)
}

func geoLookupMaxRetries(numMeasurements int) int {
	maxRetries := numMeasurements - 1
	if maxRetries < 0 {
		return 0
	}
	if maxRetries > 5 {
		return 5
	}
	return maxRetries
}

func normalizeGeoLookupAttempt(attempt int) int {
	if attempt < 0 {
		return 0
	}
	if attempt > 4 {
		return 4
	}
	return attempt
}

func geoTimeoutForAttempt(attempt int) time.Duration {
	attempt = normalizeGeoLookupAttempt(attempt)
	timeout := 2 + attempt
	if timeout > 6 {
		timeout = 6
	}
	return time.Duration(timeout) * time.Second
}

func lookupGeoSourceWithContext(ctx context.Context, cacheKey string, fn func() (any, error)) (any, error) {
	if ctx == nil || ctx.Done() == nil {
		v, err, _ := ipGeoSF.Do(cacheKey, fn)
		return v, err
	}

	resultCh := ipGeoSF.DoChan(cacheKey, fn)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-resultCh:
		return result.Val, result.Err
	}
}

func lookupGeoWithRetry(c Config, cacheKey, query string, dn42 bool) (*ipgeo.IPGeoData, error) {
	if cacheVal, ok := geoCache.Load(cacheKey); ok {
		if g, ok := cacheVal.(*ipgeo.IPGeoData); ok && g != nil {
			return g, nil
		}
	}

	ctx := c.Context
	if ctx == nil {
		ctx = context.Background()
	}

	typeErr := "ipgeo: nil or bad type from singleflight"
	lookupErr := "ipgeo: lookup failed without specific error"
	if dn42 {
		typeErr += " (DN42)"
		lookupErr += " (DN42)"
	}

	var lastErr error
	startAttempt := normalizeGeoLookupAttempt(c.GeoLookupOffset)
	endAttempt := startAttempt + geoLookupMaxRetries(c.NumMeasurements)
	for attempt := startAttempt; attempt <= endAttempt; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		timeout := geoTimeoutForAttempt(attempt)
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return nil, context.DeadlineExceeded
			}
			if remaining < timeout {
				timeout = remaining
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		v, err := lookupGeoSourceWithContext(attemptCtx, cacheKey, func() (any, error) {
			return c.IPGeoSource(query, timeout, c.Lang, c.Maptrace)
		})
		cancel()
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}

		geo, ok := v.(*ipgeo.IPGeoData)
		if !ok || geo == nil {
			lastErr = errors.New(typeErr)
			continue
		}

		geoCache.Store(cacheKey, geo)
		return geo, nil
	}

	if lastErr == nil {
		lastErr = errors.New(lookupErr)
	}
	return nil, lastErr
}

func lookupPTR(ctx context.Context, ipStr string) []string {
	ptrs, err := util.LookupAddrWithContext(ctx, ipStr)
	if err != nil {
		return nil
	}
	if len(ptrs) > 0 {
		return ptrs
	}
	return nil
}

func applyPTRResult(h *Hop, ptrs []string) {
	if len(ptrs) > 0 {
		h.Hostname = CanonicalHostname(ptrs[0])
	}
}

func startPTRLookup(ctx context.Context, ipStr string) <-chan []string {
	rDNSCh := make(chan []string, 1)
	go func() {
		select {
		case rDNSCh <- lookupPTR(ctx, ipStr):
		default:
		}
	}()
	return rDNSCh
}

func (h *Hop) resolveDN42Metadata(c Config, ipStr string) error {
	combined := ipStr
	if c.RDNS && h.Hostname == "" {
		applyPTRResult(h, lookupPTR(c.Context, ipStr))
		if h.Hostname != "" {
			combined = ipStr + "," + h.Hostname
		}
	}
	if c.IPGeoSource == nil {
		return nil
	}

	geo, err := lookupGeoWithRetry(c, combined, combined, true)
	if err != nil {
		h.Geo = timeoutGeo()
		return err
	}
	h.Geo = geo
	return nil
}

func (h *Hop) startGeoLookup(c Config, ipStr string) <-chan error {
	ipGeoCh := make(chan error, 1)
	go func() {
		if c.IPGeoSource == nil || (h.Geo != nil && !isPendingGeo(h.Geo)) {
			ipGeoCh <- nil
			return
		}

		h.Lang = c.Lang
		if g, ok := ipgeo.Filter(ipStr); ok {
			h.Geo = g
			ipGeoCh <- nil
			return
		}

		geo, err := lookupGeoWithRetry(c, ipStr, ipStr, false)
		if err == nil {
			h.Geo = geo
		}
		ipGeoCh <- err
	}()
	return ipGeoCh
}

func (h *Hop) waitForGeoAndPTR(c Config, ipGeoCh <-chan error, rDNSStarted bool, rDNSCh <-chan []string) error {
	if c.AlwaysWaitRDNS {
		if rDNSStarted {
			select {
			case ptrs := <-rDNSCh:
				applyPTRResult(h, ptrs)
			case <-time.After(1 * time.Second):
			}
		}
		err := <-ipGeoCh
		if err != nil {
			h.Geo = timeoutGeo()
		}
		return err
	}

	if rDNSStarted {
		select {
		case err := <-ipGeoCh:
			if err != nil {
				h.Geo = timeoutGeo()
			}
			return err
		case ptrs := <-rDNSCh:
			applyPTRResult(h, ptrs)
			err := <-ipGeoCh
			if err != nil {
				h.Geo = timeoutGeo()
			}
			return err
		}
	}

	err := <-ipGeoCh
	if err != nil {
		h.Geo = timeoutGeo()
	}
	return err
}

func (h *Hop) fetchIPData(c Config) error {
	ipStr := h.Address.String()
	if c.DN42 {
		return h.resolveDN42Metadata(c, ipStr)
	}

	ipGeoCh := h.startGeoLookup(c, ipStr)
	rDNSStarted := c.RDNS && h.Hostname == ""
	var rDNSCh <-chan []string
	if rDNSStarted {
		rDNSCh = startPTRLookup(c.Context, ipStr)
	}
	return h.waitForGeoAndPTR(c, ipGeoCh, rDNSStarted, rDNSCh)
}

// parse 安全解析十六进制子串 s 为无符号整数
func parse(s string, bitSize int) (uint64, bool) {
	if len(s) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, bitSize)
	if err != nil {
		return 0, false
	}
	return v, true
}

// findValid 在十六进制字符串 hexStr 中截取从 ICMP 扩展头开始的部分
func findValid(hexStr string) string {
	n := len(hexStr)
	// 至少要能容纳 4B 扩展头，且 hexStr 的长度必须为偶数
	if n < 8 || n%2 != 0 {
		return ""
	}

	// 从尾到头以 4B 为单位扫描（1B = 2 hex digits）
	for i := n - 8; i >= 0; i -= 8 {
		// 直接匹配 "2000"
		if hexStr[i:i+4] != "2000" {
			continue
		}

		// 处理扩展头 4B 后的剩余部分
		remHex := n - (i + 8) // 剩余的 hex 个数
		if remHex <= 0 {
			continue
		}

		remBytes := remHex / 2
		// 剩余部分长度必须 ≥ 8B
		if remBytes >= 8 {
			return hexStr[i:]
		}

		// 否则继续向左寻找更早的 "2000"
	}
	return ""
}

func extractMPLS(msg internal.ReceivedMessage, disableMPLS bool) []string {
	if disableMPLS {
		return nil
	}

	// 将整包转换为十六进制字符串
	hexStr := fmt.Sprintf("%x", msg.Msg)

	// 调用 findValid 截取从 ICMP 扩展头开始的字符串
	extStr := findValid(hexStr)
	if extStr == "" {
		return nil
	}

	var mplsLSEList []string
	n := len(extStr)

	// 先逐对象检查 Class 是否为 MPLS Label Stack Class (1)
	for j := 8; j+8 <= n; {
		// 对象头：Length(2B) | Class(1B) | C-Type(1B)
		lengthU, ok := parse(extStr[j:j+4], 16)
		if !ok || lengthU < 4 {
			return nil
		}
		objLenBytes := int(lengthU)
		objLenHex := objLenBytes * 2
		if j+objLenHex > n {
			return nil
		}

		// 读取 Class 的值
		classU, ok := parse(extStr[j+4:j+6], 8)
		if !ok {
			return nil
		}
		class := int(classU)

		if class == 1 {
			// 去掉扩展头与 MPLS 对象头，只保留 MPLS 对象负载
			payloadStart := j + 8
			payloadEnd := j + objLenHex
			if payloadEnd <= payloadStart {
				return nil
			}
			mplsPayload := extStr[payloadStart:payloadEnd] // 仅 LSE 区域
			if len(mplsPayload)%8 != 0 {                   // 每个 LSE = 4B = 8 hex digits
				return nil
			}

			// 逐个 LSE 解析并追加到 mplsLSEList
			for off := 0; off+8 <= len(mplsPayload); off += 8 {
				vU, ok := parse(mplsPayload[off:off+8], 32)
				if !ok {
					return nil
				}
				v := uint32(vU)

				lbl := (v >> 12) & 0xFFFFF // 20 bits
				tc := (v >> 9) & 0x7       // 3 bits
				s := (v >> 8) & 0x1        // 1 bit
				ttl := v & 0xFF            // 8 bits

				mplsLSEList = append(mplsLSEList, fmt.Sprintf("[MPLS: Lbl %d, TC %d, S %d, TTL %d]", lbl, tc, s, ttl))
			}
		}

		// 跳到下一个对象
		j += objLenHex
	}
	return mplsLSEList
}
