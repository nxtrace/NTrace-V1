package cmd

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/nxtrace/NTrace-core/internal/mtrsession"
	"github.com/nxtrace/NTrace-core/printer"
	"github.com/nxtrace/NTrace-core/trace"
)

type mtrReplayCursor struct {
	session *mtrsession.Session
	state   *trace.MTRReplayState
	history *printer.MTRHistoryStore
	pending *mtrsession.Record
	end     *mtrsession.End
	cursor  time.Duration
	eof     bool
}

func readMTRReplay(ctx context.Context, r *mtrsession.Reader, at time.Duration) (*mtrReplayCursor, error) {
	if err := r.Rewind(); err != nil {
		return nil, err
	}
	c := &mtrReplayCursor{history: printer.NewMTRHistoryStore(printer.MTRHistoryWindow)}
	if err := c.advance(ctx, r, at); err != nil {
		return nil, err
	}
	if c.session == nil {
		return nil, errors.New("recording has no session header")
	}
	return c, nil
}

func (c *mtrReplayCursor) advance(ctx context.Context, r *mtrsession.Reader, at time.Duration) error {
	for !c.eof {
		if err := ctx.Err(); err != nil {
			return err
		}
		var record mtrsession.Record
		if c.pending != nil {
			record = *c.pending
			c.pending = nil
		} else {
			var err error
			record, err = r.Next()
			if errors.Is(err, io.EOF) {
				c.eof = true
				break
			}
			if err != nil {
				return err
			}
		}
		if time.Duration(record.ElapsedNS) > at {
			c.pending = &record
			break
		}
		c.cursor = time.Duration(record.ElapsedNS)
		if err := c.apply(record); err != nil {
			return err
		}
	}
	if at != time.Duration(1<<63-1) {
		c.cursor = at
	}
	return nil
}

func (c *mtrReplayCursor) apply(record mtrsession.Record) error {
	switch record.Type {
	case mtrsession.StartEvent:
		c.session = record.Session
		maxHops, bounded := 30, false
		if p := c.session.EffectiveParameters; p != nil {
			maxHops = p.MaxHops
			bounded = p.MaxPerHop > 0
		}
		c.state = trace.NewMTRReplayState(bounded, maxHops)
		return nil
	case mtrsession.EndEvent:
		c.end = record.End
		return nil
	}
	if c.state == nil {
		return errors.New("recording event precedes session header")
	}
	if err := c.state.Apply(record.MTRSessionEvent); err != nil {
		return err
	}
	if record.Type == trace.MTRSessionResetEvent {
		c.history.Reset()
	}
	if p := record.Probe; p != nil {
		now := c.session.StartedAt.Add(time.Duration(record.ElapsedNS))
		age := max(time.Duration(0), record.Timestamp.Sub(p.CompletedAt))
		c.history.AddProbeEventAt(trace.MTRProbeEvent{TTL: p.TTL, Success: p.Success, RTT: p.RTT, Timestamp: now.Add(-age)}, now)
	}
	return nil
}
