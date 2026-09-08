package mtrsession

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
)

type writeSyncCloser interface {
	io.Writer
	Sync() error
	Close() error
}

// Writer writes each complete event before returning. Finish syncs and closes
// the file. A failed write is sticky: later calls never append to a bad tail.
type Writer struct {
	mu     sync.Mutex
	file   writeSyncCloser
	start  time.Time
	state  recordState
	err    error
	closed bool
}

// Open exclusively creates a private file. Existing files, including symlinks,
// are never overwritten or appended to.
func Open(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return &Writer{file: f}, nil
}

func (w *Writer) Start(session Session) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if session.StartedAt.IsZero() {
		session.StartedAt = time.Now()
	}
	w.start = session.StartedAt
	session.StartedAt = session.StartedAt.UTC()
	return w.writeLocked(Record{
		MTRSessionEvent: trace.MTRSessionEvent{Type: StartEvent},
		Timestamp:       session.StartedAt.UTC(), Session: &session,
	})
}

func (w *Writer) Event(event trace.MTRSessionEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if event.At.IsZero() {
		event.At = time.Now()
	}
	return w.writeLocked(Record{MTRSessionEvent: event, Timestamp: event.At.UTC(), ElapsedNS: w.elapsed(event.At)})
}

func (w *Writer) elapsed(at time.Time) int64 {
	value := int64(at.Sub(w.start))
	if value < w.state.elapsed {
		value = w.state.elapsed
	}
	return value
}

func (w *Writer) writeLocked(record Record) error {
	if w.closed {
		return ErrClosed
	}
	if w.err != nil {
		return w.err
	}
	record.Format, record.SchemaVersion, record.Seq = FormatName, SchemaVersion, w.state.seq+1
	state := w.state
	if w.err = state.accept(record); w.err != nil {
		return w.err
	}
	var data []byte
	data, w.err = json.Marshal(record)
	if w.err != nil {
		return w.err
	}
	if len(data)+1 > MaxLineBytes {
		w.err = ErrLineTooLarge
		return w.err
	}
	data = append(data, '\n')
	var n int
	n, w.err = w.file.Write(data)
	if w.err == nil && n != len(data) {
		w.err = io.ErrShortWrite
	}
	if w.err == nil {
		w.state = state
	}
	return w.err
}

// Finish is idempotent and checks both Sync and Close, including after a write
// failure. The first failed record is never retried.
func (w *Writer) Finish(end End) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.err
	}
	if end.EndedAt.IsZero() {
		end.EndedAt = time.Now()
	}
	elapsed := w.elapsed(end.EndedAt)
	end.EndedAt = end.EndedAt.UTC()
	_ = w.writeLocked(Record{
		MTRSessionEvent: trace.MTRSessionEvent{Type: EndEvent, Generation: w.state.generation},
		Timestamp:       end.EndedAt, ElapsedNS: elapsed, End: &end,
	})
	return w.closeLocked()
}

// Close preserves an unfinished file for recovery without inventing an end.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeLocked()
}

func (w *Writer) closeLocked() error {
	if !w.closed {
		w.closed = true
		w.err = errors.Join(w.err, w.file.Sync(), w.file.Close())
	}
	return w.err
}
