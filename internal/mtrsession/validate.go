package mtrsession

import (
	"errors"
	"fmt"
	"net"

	"github.com/nxtrace/NTrace-core/trace"
)

var (
	ErrLineTooLarge = errors.New("MTR session record exceeds 1 MiB")
	ErrClosed       = errors.New("MTR session file is closed")
)

type recordState struct {
	seq        uint64
	elapsed    int64
	generation uint64
	maxHops    int
	ended      bool
}

func (s *recordState) accept(r Record) error {
	if r.Format != FormatName {
		return errors.New("not a NextTrace MTR session file")
	}
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported MTR session schema version %d", r.SchemaVersion)
	}
	if s.ended {
		return errors.New("record follows MTR session end")
	}
	if r.Seq != s.seq+1 {
		return fmt.Errorf("MTR session sequence: got %d, expected %d", r.Seq, s.seq+1)
	}
	if r.ElapsedNS < s.elapsed || r.Timestamp.IsZero() {
		return errors.New("invalid MTR session timestamp")
	}
	if r.ProbeAgeNS != nil && (r.Type != trace.MTRSessionProbeEvent || *r.ProbeAgeNS < 0) {
		return errors.New("invalid MTR session probe age")
	}
	if s.seq == 0 {
		if err := s.acceptStart(r); err != nil {
			return err
		}
	} else if err := s.acceptEvent(r); err != nil {
		return err
	}
	s.seq, s.elapsed, s.generation = r.Seq, r.ElapsedNS, r.Generation
	return nil
}

func (s *recordState) acceptStart(r Record) error {
	if r.Type != StartEvent || r.Session == nil || r.End != nil || r.Probe != nil || r.Metadata != nil || r.PathEnd != nil || r.Generation != 0 || r.ElapsedNS != 0 {
		return errors.New("MTR session must begin with a start record")
	}
	if !r.Timestamp.Equal(r.Session.StartedAt) {
		return errors.New("MTR session start timestamp does not match header")
	}
	if p := r.Session.EffectiveParameters; p != nil {
		if p.MaxHops < 1 || p.MaxHops > 255 || p.BeginHop < 1 || p.BeginHop > p.MaxHops || p.MaxPerHop < 0 || p.HopIntervalMs <= 0 || p.TimeoutMs <= 0 || p.ParallelRequests <= 0 || p.TOS < 0 || p.TOS > 255 {
			return errors.New("invalid effective MTR session parameters")
		}
		s.maxHops = p.MaxHops
	}
	return nil
}

func (s *recordState) acceptEvent(r Record) error {
	if r.Session != nil {
		return errors.New("unexpected MTR session header")
	}
	expectedGeneration := s.generation
	if r.Type == trace.MTRSessionResetEvent {
		expectedGeneration++
	}
	if r.Generation != expectedGeneration {
		return errors.New("invalid MTR session generation")
	}
	if r.Type == EndEvent {
		if r.End == nil || r.Probe != nil || r.Metadata != nil || r.PathEnd != nil || !r.End.EndedAt.Equal(r.Timestamp) || !validEndReason(r.End) {
			return errors.New("invalid MTR session end")
		}
		s.ended = true
		return nil
	}
	if r.End != nil {
		return errors.New("unexpected MTR session end payload")
	}
	switch r.Type {
	case trace.MTRSessionProbeEvent:
		if r.Probe == nil || r.Metadata != nil || r.PathEnd != nil || r.Probe.TTL < 1 || r.Probe.TTL > s.maxHops || r.Probe.RTT < 0 || r.Probe.CompletedAt.IsZero() {
			return errors.New("invalid MTR session probe")
		}
		if response := r.Probe.Response; response != nil {
			if !r.Probe.Success || net.ParseIP(r.Probe.IP) == nil {
				return errors.New("MTR session response requires a successful probe with a valid address")
			}
			switch response.Kind {
			case trace.MTRResponseTransit, trace.MTRResponseDestination, trace.MTRResponseUnreachable:
			default:
				return fmt.Errorf("invalid MTR session response kind %q", response.Kind)
			}
		}
	case trace.MTRSessionMetadataEvent:
		if r.Metadata == nil || r.Metadata.IP == "" || r.Probe != nil || r.PathEnd != nil {
			return errors.New("invalid MTR session metadata")
		}
	case trace.MTRSessionPathEndEvent:
		if r.Probe != nil || r.Metadata != nil {
			return errors.New("invalid MTR session path end")
		}
	case trace.MTRSessionPauseEvent, trace.MTRSessionResumeEvent, trace.MTRSessionResetEvent:
		if r.Probe != nil || r.Metadata != nil || r.PathEnd != nil {
			return errors.New("unexpected MTR session control payload")
		}
	default:
		return fmt.Errorf("unknown MTR session event %q", r.Type)
	}
	return nil
}

// validEndReason accepts only combinations emitted by the recording lifecycle.
func validEndReason(end *End) bool {
	switch end.EndReason {
	case "completed":
		return end.Error == nil && end.Signal == ""
	case "interrupted":
		return end.Error == nil && (end.Signal == "" || end.Signal == "SIGINT" || end.Signal == "SIGTERM")
	case "error":
		return end.Signal == "" && end.Error != nil && end.Error.Stage != "" && end.Error.Message != ""
	default:
		return false
	}
}
