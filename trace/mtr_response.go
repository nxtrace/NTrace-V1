package trace

import (
	"net"
	"reflect"
	"sort"
)

// MTRProbeResponse describes the semantic result of one MTR probe.
type MTRProbeResponse struct {
	Kind        string `json:"kind"`
	Description string `json:"description,omitempty"`
	Marker      string `json:"marker,omitempty"`
	responderIP string
}

const (
	MTRResponseTransit     = "transit"
	MTRResponseDestination = "destination"
	MTRResponseUnreachable = "unreachable"
)

type mtrTTLEvidence struct {
	destination          *MTRProbeResponse
	transit              *MTRProbeResponse
	unreachable          *MTRProbeResponse
	live                 *MTRProbeResponse
	destinationResponses map[string]struct{}
	destinationMarkers   map[string]struct{}
	unreachableResponses map[string]struct{}
	unreachableMarkers   map[string]struct{}
}

// mtrPathTracker owns the response evidence used to derive an MTR path edge.
// Bounded runs accumulate evidence; unbounded runs keep destination evidence
// sticky while allowing later transit replies to reopen provisional edges.
type mtrPathTracker struct {
	bounded  bool
	maxHops  int
	evidence map[int]*mtrTTLEvidence
	current  *StopReason
	onChange func(*StopReason)
}

func newMTRPathTracker(bounded bool, maxHops int, onChange func(*StopReason)) *mtrPathTracker {
	return &mtrPathTracker{
		bounded:  bounded,
		maxHops:  maxHops,
		evidence: make(map[int]*mtrTTLEvidence),
		onChange: onChange,
	}
}

func (t *mtrPathTracker) observe(ttl int, response *MTRProbeResponse) bool {
	if response == nil {
		return false
	}
	return t.observeWithDetails(ttl, response, []string{response.Description}, []string{response.Marker})
}

func (t *mtrPathTracker) observeWithDetails(ttl int, response *MTRProbeResponse, responses, markers []string) bool {
	if t == nil || ttl <= 0 || response == nil {
		return false
	}
	if response.Kind != MTRResponseDestination && response.Kind != MTRResponseTransit && response.Kind != MTRResponseUnreachable {
		return false
	}

	evidence := t.evidence[ttl]
	if evidence == nil {
		evidence = &mtrTTLEvidence{}
		t.evidence[ttl] = evidence
	}
	response = cloneMTRProbeResponse(response)

	if response.Kind == MTRResponseDestination {
		evidence.destination = response
		if t.bounded {
			addMTRStopDetails(&evidence.destinationResponses, responses)
			addMTRStopDetails(&evidence.destinationMarkers, markers)
		}
	} else if evidence.destination == nil {
		if t.bounded {
			switch response.Kind {
			case MTRResponseTransit:
				evidence.transit = response
			case MTRResponseUnreachable:
				evidence.unreachable = response
				addMTRStopDetails(&evidence.unreachableResponses, responses)
				addMTRStopDetails(&evidence.unreachableMarkers, markers)
			}
		} else {
			evidence.live = response
		}
	}
	return t.recompute()
}

func (t *mtrPathTracker) observeStopReason(reason *StopReason) bool {
	if t == nil || reason == nil || reason.Hop <= 0 {
		return false
	}
	response := &MTRProbeResponse{Description: firstString(reason.Responses)}
	switch reason.Reason {
	case StopReasonDestination:
		response.Kind = MTRResponseDestination
	case StopReasonUnreachable:
		response.Kind = MTRResponseUnreachable
		response.Marker = firstString(reason.Markers)
	default:
		return false
	}
	return t.observeWithDetails(reason.Hop, response, reason.Responses, reason.Markers)
}

func (t *mtrPathTracker) responseAt(ttl int) *MTRProbeResponse {
	if t == nil {
		return nil
	}
	evidence := t.evidence[ttl]
	if evidence == nil {
		return nil
	}
	if evidence.destination != nil {
		return cloneMTRProbeResponse(evidence.destination)
	}
	if t.bounded {
		if evidence.transit != nil {
			return cloneMTRProbeResponse(evidence.transit)
		}
		return cloneMTRProbeResponse(evidence.unreachable)
	}
	return cloneMTRProbeResponse(evidence.live)
}

func (t *mtrPathTracker) pathEnd() *StopReason {
	if t == nil {
		return nil
	}
	return cloneStopReason(t.current)
}

func (t *mtrPathTracker) completeAtMaxHops() bool {
	if t == nil || t.current != nil || t.maxHops <= 0 {
		return false
	}
	t.current = &StopReason{Hop: t.maxHops, Reason: StopReasonMaxHops}
	t.notify()
	return true
}

func (t *mtrPathTracker) reset() bool {
	if t == nil {
		return false
	}
	hadPathEnd := t.current != nil
	t.evidence = make(map[int]*mtrTTLEvidence)
	t.current = nil
	if hadPathEnd {
		t.notify()
	}
	return hadPathEnd
}

func (t *mtrPathTracker) recompute() bool {
	ttls := make([]int, 0, len(t.evidence))
	for ttl := range t.evidence {
		ttls = append(ttls, ttl)
	}
	sort.Ints(ttls)

	var next *StopReason
	for _, ttl := range ttls {
		response := t.responseAt(ttl)
		if response != nil && response.Kind == MTRResponseDestination {
			next = t.stopReasonFromEvidence(ttl, StopReasonDestination, response)
			break
		}
	}
	if next == nil {
		next = t.firstUnreachable(ttls)
	}
	if reflect.DeepEqual(t.current, next) {
		return false
	}
	t.current = next
	t.notify()
	return true
}

func (t *mtrPathTracker) firstUnreachable(ttls []int) *StopReason {
	for _, ttl := range ttls {
		response := t.responseAt(ttl)
		if response != nil && response.Kind == MTRResponseUnreachable {
			return t.stopReasonFromEvidence(ttl, StopReasonUnreachable, response)
		}
	}
	return nil
}

func (t *mtrPathTracker) stopReasonFromEvidence(ttl int, reason string, response *MTRProbeResponse) *StopReason {
	result := stopReasonFromMTRResponse(ttl, reason, response)
	if !t.bounded {
		return result
	}
	evidence := t.evidence[ttl]
	if evidence == nil {
		return result
	}
	switch reason {
	case StopReasonDestination:
		result.Responses = sortedResponseDetails(evidence.destinationResponses)
		result.Markers = sortedResponseDetails(evidence.destinationMarkers)
	case StopReasonUnreachable:
		result.Responses = sortedResponseDetails(evidence.unreachableResponses)
		result.Markers = sortedResponseDetails(evidence.unreachableMarkers)
	}
	return result
}

func addMTRStopDetails(details *map[string]struct{}, values []string) {
	for _, value := range values {
		if value == "" {
			continue
		}
		if *details == nil {
			*details = make(map[string]struct{})
		}
		(*details)[value] = struct{}{}
	}
}

func (t *mtrPathTracker) notify() {
	if t.onChange != nil {
		t.onChange(cloneStopReason(t.current))
	}
}

func stopReasonFromMTRResponse(ttl int, reason string, response *MTRProbeResponse) *StopReason {
	result := &StopReason{Hop: ttl, Reason: reason}
	if response == nil {
		return result
	}
	if response.Description != "" {
		result.Responses = []string{response.Description}
	}
	if response.Marker != "" {
		result.Markers = []string{response.Marker}
	}
	return result
}

func cloneMTRProbeResponse(response *MTRProbeResponse) *MTRProbeResponse {
	if response == nil {
		return nil
	}
	clone := *response
	return &clone
}

func mtrProbeResponseWithPeer(response *MTRProbeResponse, peer net.Addr) *MTRProbeResponse {
	response = cloneMTRProbeResponse(response)
	if response != nil {
		response.responderIP = mtrAddrString(peer)
	}
	return response
}

func mtrProbeResponseForStat(tracker *mtrPathTracker, stat MTRHopStat) *MTRProbeResponse {
	response := tracker.responseAt(stat.TTL)
	if response == nil || response.responderIP == "" || response.responderIP == stat.IP {
		return response
	}
	return nil
}

func cloneStopReason(reason *StopReason) *StopReason {
	if reason == nil {
		return nil
	}
	clone := *reason
	clone.Responses = append([]string(nil), reason.Responses...)
	clone.Markers = append([]string(nil), reason.Markers...)
	return &clone
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func mtrProbeResponseFromProbe(response probeResponse) *MTRProbeResponse {
	result := &MTRProbeResponse{
		Description: response.detail,
		Marker:      response.marker,
		responderIP: response.responderIP,
	}
	switch response.kind {
	case probeResponseTransit:
		result.Kind = MTRResponseTransit
	case probeResponseDestination:
		result.Kind = MTRResponseDestination
	case probeResponseUnreachable:
		result.Kind = MTRResponseUnreachable
	default:
		return nil
	}
	return result
}

func probeResponseFromMTR(response *MTRProbeResponse) probeResponse {
	if response == nil {
		return probeResponse{}
	}
	result := probeResponse{
		detail:      response.Description,
		marker:      response.Marker,
		responderIP: response.responderIP,
	}
	switch response.Kind {
	case MTRResponseTransit:
		result.kind = probeResponseTransit
	case MTRResponseDestination:
		result.kind = probeResponseDestination
	case MTRResponseUnreachable:
		result.kind = probeResponseUnreachable
	}
	return result
}

func bestMTRProbeResponse(res *Result, ttl int) *MTRProbeResponse {
	if res == nil || ttl <= 0 {
		return nil
	}
	res.lock.RLock()
	responses := append([]probeResponse(nil), res.responses[ttl]...)
	stopReason := cloneStopReason(res.StopReason)
	res.lock.RUnlock()
	best := probeResponse{}
	for _, response := range responses {
		if probeResponsePriority(response.kind) > probeResponsePriority(best.kind) {
			best = response
		}
	}
	if response := mtrProbeResponseFromProbe(best); response != nil {
		return mtrProbeResponseWithResultPeer(response, res, ttl)
	}
	if stopReason != nil && stopReason.Hop == ttl {
		tracker := newMTRPathTracker(true, ttl, nil)
		tracker.observeStopReason(stopReason)
		return mtrProbeResponseWithResultPeer(tracker.responseAt(ttl), res, ttl)
	}
	return nil
}

func mtrProbeResponseWithResultPeer(response *MTRProbeResponse, res *Result, ttl int) *MTRProbeResponse {
	if response == nil || res == nil || ttl <= 0 {
		return response
	}
	if response.responderIP != "" {
		return response
	}
	res.lock.RLock()
	defer res.lock.RUnlock()
	if ttl > len(res.Hops) {
		return response
	}
	for _, hop := range res.Hops[ttl-1] {
		if hop.Success && hop.Address != nil {
			return mtrProbeResponseWithPeer(response, hop.Address)
		}
	}
	return response
}

func probeResponsePriority(kind probeResponseKind) int {
	switch kind {
	case probeResponseDestination:
		return 3
	case probeResponseTransit:
		return 2
	case probeResponseUnreachable:
		return 1
	default:
		return 0
	}
}
