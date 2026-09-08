package cmd

import (
	"sync"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
)

// One worker owns all frame writes, including input and resize redraws. Probe
// callbacks only replace the immutable latest snapshot and coalesce a wakeup.
func startMTRRedraw(notify chan struct{}, size func() (int, int), render trace.MTROnSnapshot) (trace.MTROnSnapshot, func()) {
	var mu sync.Mutex
	var latest []trace.MTRHopStat
	iteration := 0
	stopped := false
	stop, done := make(chan struct{}), make(chan struct{})
	draw := func() {
		mu.Lock()
		stats, n := latest, iteration
		mu.Unlock()
		render(n, stats)
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		width, height := size()
		draw()
		for {
			select {
			case <-stop:
				draw()
				return
			case <-notify:
				draw()
			case <-ticker.C:
				w, h := size()
				if w != width || h != height {
					width, height = w, h
					draw()
				}
			}
		}
	}()
	snapshot := func(n int, stats []trace.MTRHopStat) {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		iteration = n
		latest = cloneMTRDisplayStats(stats)
		select {
		case notify <- struct{}{}:
		default:
		}
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() { mu.Lock(); stopped = true; mu.Unlock(); close(stop); <-done })
	}
	return snapshot, cleanup
}

func cloneMTRDisplayStats(stats []trace.MTRHopStat) []trace.MTRHopStat {
	result := append([]trace.MTRHopStat(nil), stats...)
	for i := range result {
		s := &result[i]
		s.MPLS = append([]string(nil), s.MPLS...)
		if s.Geo != nil {
			geo := *s.Geo
			s.Geo = &geo
		}
		if s.Response != nil {
			response := *s.Response
			s.Response = &response
		}
	}
	return result
}
