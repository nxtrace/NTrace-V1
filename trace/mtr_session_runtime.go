package trace

import "time"

// Session events are emitted from the scheduler goroutine only. A recorder
// failure cancels all workers before another probe can be scheduled. Applied
// changes must still be delivered when cancellation races with their accounting.
func (rt *mtrSchedulerRuntime) emitSessionEvent(event MTRSessionEvent) bool {
	if rt.cfg.OnEvent == nil {
		return true
	}
	event.At = time.Now()
	event.Generation = rt.generation
	event.Iteration = rt.computeIteration()
	if err := rt.cfg.OnEvent(event); err != nil {
		rt.workers.cancel(err)
		return false
	}
	return true
}

func (rt *mtrSchedulerRuntime) emitSessionProbe(hop Hop, response *MTRProbeResponse, doneAt time.Time) bool {
	if rt.cfg.OnEvent == nil {
		return true
	}
	return rt.emitSessionEvent(MTRSessionEvent{
		Type: MTRSessionProbeEvent,
		Probe: &MTRSessionProbe{
			TTL: hop.TTL, IP: mtrAddrString(hop.Address), Host: hop.Hostname,
			Success: hop.Success, RTT: hop.RTT, CompletedAt: doneAt,
			Geo: cloneMTRGeo(hop.Geo), MPLS: append([]string(nil), hop.MPLS...),
			Response: cloneMTRProbeResponse(response),
		},
	})
}

// The scheduler observes path evidence before it accounts the cause probe.
// Persist the cause first while retaining the legacy OnPathEnd callback order.
func (rt *mtrSchedulerRuntime) flushSessionPath() bool {
	if !rt.sessionPathChanged {
		return true
	}
	reason := rt.sessionPathEnd
	rt.sessionPathChanged = false
	rt.sessionPathEnd = nil
	return rt.emitSessionEvent(MTRSessionEvent{Type: MTRSessionPathEndEvent, PathEnd: reason})
}

func (rt *mtrSchedulerRuntime) emitSessionMetadata(ip string, patch mtrMetadataPatch) bool {
	if rt.cfg.OnEvent == nil {
		return true
	}
	return rt.emitSessionEvent(MTRSessionEvent{
		Type:     MTRSessionMetadataEvent,
		Metadata: &MTRSessionMetadata{IP: ip, Host: patch.host, Geo: cloneMTRGeo(patch.geo)},
	})
}
