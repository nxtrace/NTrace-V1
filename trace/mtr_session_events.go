package trace

import (
	"fmt"
	"net"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
)

const (
	MTRSessionProbeEvent    = "probe"
	MTRSessionMetadataEvent = "metadata"
	MTRSessionPauseEvent    = "pause"
	MTRSessionResumeEvent   = "resume"
	MTRSessionResetEvent    = "reset"
	MTRSessionPathEndEvent  = "path_end"
)

// MTRSessionEvent describes an applied change to a per-hop MTR session.
// OnEvent observers run serially in scheduler order. At is the application time;
// a probe's CompletedAt may precede At and is not an event ordering key.
// File formats supply their own version, sequence and relative time envelope.
type MTRSessionEvent struct {
	Type       string              `json:"type"`
	Generation uint64              `json:"generation"`
	At         time.Time           `json:"-"`
	Iteration  int                 `json:"iteration,omitempty"`
	Probe      *MTRSessionProbe    `json:"probe,omitempty"`
	Metadata   *MTRSessionMetadata `json:"metadata,omitempty"`
	PathEnd    *StopReason         `json:"path_end"`
}

// MTRSessionProbe contains exactly the hop passed to MTRAggregator.Update.
// RTT is serialized as integer nanoseconds to preserve the original arithmetic.
type MTRSessionProbe struct {
	TTL         int               `json:"ttl"`
	IP          string            `json:"ip,omitempty"`
	Host        string            `json:"host,omitempty"`
	Success     bool              `json:"success"`
	RTT         time.Duration     `json:"rtt_ns"`
	CompletedAt time.Time         `json:"completed_at"`
	Geo         *ipgeo.IPGeoData  `json:"geo,omitempty"`
	MPLS        []string          `json:"mpls,omitempty"`
	Response    *MTRProbeResponse `json:"response,omitempty"`
}

// MTRSessionMetadata patches all existing rows for an address without counting
// another probe. Empty fields retain their existing values.
type MTRSessionMetadata struct {
	IP   string           `json:"ip"`
	Host string           `json:"host,omitempty"`
	Geo  *ipgeo.IPGeoData `json:"geo,omitempty"`
}

// MTRReplayState rebuilds statistics without creating probes or looking up
// metadata. Apply must be called in recorded sequence order, not timestamp order.
type MTRReplayState struct {
	agg        *MTRAggregator
	tracker    *mtrPathTracker
	maxHops    int
	generation uint64
	iteration  int
	paused     bool
}

func NewMTRReplayState(bounded bool, maxHops int) *MTRReplayState {
	if maxHops <= 0 {
		maxHops = 30
	}
	maxHops = min(maxHops, maxMTRHopCount)
	return &MTRReplayState{
		agg:     NewMTRAggregator(),
		tracker: newMTRPathTracker(bounded, maxHops, nil),
		maxHops: maxHops,
	}
}

func (s *MTRReplayState) Apply(event MTRSessionEvent) error {
	if event.Type == MTRSessionResetEvent {
		if event.Generation != s.generation+1 {
			return fmt.Errorf("mtr replay: invalid reset generation %d", event.Generation)
		}
		s.generation = event.Generation
		s.agg.Reset()
		s.tracker.reset()
		s.iteration = 0
		return nil
	}
	if event.Generation != s.generation {
		return fmt.Errorf("mtr replay: event generation %d does not match %d", event.Generation, s.generation)
	}
	switch event.Type {
	case MTRSessionProbeEvent:
		return s.applyProbe(event)
	case MTRSessionMetadataEvent:
		if event.Metadata == nil || net.ParseIP(event.Metadata.IP) == nil {
			return fmt.Errorf("mtr replay: invalid metadata address")
		}
		patch := event.Metadata
		s.agg.PatchMetadataByIP(patch.IP, patch.Host, patch.Geo)
	case MTRSessionPauseEvent:
		s.paused = true
	case MTRSessionResumeEvent:
		s.paused = false
	case MTRSessionPathEndEvent:
		if reason := event.PathEnd; reason != nil {
			if reason.Hop <= 0 || reason.Hop > s.maxHops {
				return fmt.Errorf("mtr replay: invalid path end hop %d", reason.Hop)
			}
			switch reason.Reason {
			case StopReasonDestination, StopReasonUnreachable, StopReasonMaxHops:
			default:
				return fmt.Errorf("mtr replay: invalid path end reason %q", reason.Reason)
			}
			if reason.Reason == StopReasonDestination {
				s.agg.ClearAbove(reason.Hop)
			}
		}
		s.tracker.current = cloneStopReason(event.PathEnd)
	default:
		return fmt.Errorf("mtr replay: unsupported event type %q", event.Type)
	}
	return nil
}

func (s *MTRReplayState) applyProbe(event MTRSessionEvent) error {
	probe := event.Probe
	if probe == nil || probe.TTL <= 0 || probe.TTL > s.maxHops {
		return fmt.Errorf("mtr replay: invalid probe TTL")
	}
	if probe.RTT < 0 || event.Iteration < 0 {
		return fmt.Errorf("mtr replay: invalid probe timing or iteration")
	}
	var addr net.Addr
	if probe.IP != "" {
		ip := net.ParseIP(probe.IP)
		if ip == nil {
			return fmt.Errorf("mtr replay: invalid probe address %q", probe.IP)
		}
		addr = &net.IPAddr{IP: ip}
	}
	if probe.Success && addr == nil {
		return fmt.Errorf("mtr replay: successful probe has no address")
	}
	if probe.Response != nil && !probe.Success {
		return fmt.Errorf("mtr replay: failed probe cannot carry a response")
	}
	response := mtrProbeResponseWithPeer(probe.Response, addr)
	if s.tracker.observe(probe.TTL, response) {
		if reason := s.tracker.pathEnd(); reason != nil && reason.Reason == StopReasonDestination {
			s.agg.ClearAbove(reason.Hop)
		}
	}
	hops := make([][]Hop, probe.TTL)
	hops[probe.TTL-1] = []Hop{{
		TTL: probe.TTL, Address: addr, Hostname: probe.Host,
		Success: probe.Success, RTT: probe.RTT, Geo: probe.Geo, MPLS: probe.MPLS,
	}}
	s.agg.Update(&Result{Hops: hops}, 1)
	s.iteration = event.Iteration
	return nil
}

func (s *MTRReplayState) Snapshot() MTRSnapshot {
	stats := s.agg.Snapshot()
	if pathEnd := s.tracker.pathEnd(); pathEnd != nil {
		stats = filterMTRStatsAtPathEnd(stats, pathEnd.Hop)
	}
	for i := range stats {
		stats[i].Response = mtrProbeResponseForStat(s.tracker, stats[i])
	}
	return MTRSnapshot{Iteration: s.iteration, Stats: stats}
}

func (s *MTRReplayState) PathEnd() *StopReason { return s.tracker.pathEnd() }
func (s *MTRReplayState) Paused() bool         { return s.paused }
func (s *MTRReplayState) Generation() uint64   { return s.generation }
