package mtrsession

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Reader holds an open regular file and a fixed byte limit. New data appended
// while replaying is not followed, including after Rewind.
type Reader struct {
	file       *os.File
	scanner    *bufio.Scanner
	size       int64
	offset     int64
	state      recordState
	incomplete bool
	done       bool
	closed     bool
	err        error
}

func OpenReader(path string) (*Reader, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("MTR session replay requires a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("MTR session replay requires a regular file")
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	r := &Reader{file: f, size: info.Size()}
	r.reset()
	return r, nil
}

// Next returns io.EOF at the fixed end, including a recoverable partial tail.
// Call Incomplete after EOF to distinguish a complete session from a prefix.
// Invalid complete records are errors and are never silently skipped.
func (r *Reader) Next() (Record, error) {
	if r.closed {
		return Record{}, ErrClosed
	}
	if r.err != nil {
		return Record{}, r.err
	}
	if r.done {
		return Record{}, io.EOF
	}
	if !r.scanner.Scan() {
		return r.eof(r.scanner.Err())
	}
	line := r.scanner.Bytes()
	r.offset += int64(len(line))
	terminated := len(line) > 0 && line[len(line)-1] == '\n'
	var record Record
	if err := json.Unmarshal(line, &record); err != nil {
		if !terminated && r.state.seq > 0 && !r.state.ended {
			return r.eof(nil)
		}
		r.err = fmt.Errorf("invalid MTR session record %d: %w", r.state.seq+1, err)
		return Record{}, r.err
	}
	if err := r.state.accept(record); err != nil {
		r.err = fmt.Errorf("MTR session record %d: %w", r.state.seq+1, err)
		return Record{}, r.err
	}
	record.At = record.Timestamp
	return record, nil
}

func (r *Reader) eof(err error) (Record, error) {
	r.done = true
	if err == nil && r.state.seq == 0 {
		err = errors.New("MTR session has no complete start record")
	}
	if err != nil {
		r.err = err
		return Record{}, err
	}
	r.incomplete = !r.state.ended
	return Record{}, io.EOF
}

// Rewind starts a new pass over the same original file extent.
func (r *Reader) Rewind() error {
	if r.closed {
		return ErrClosed
	}
	r.reset()
	return nil
}

func (r *Reader) reset() {
	r.scanner = bufio.NewScanner(io.NewSectionReader(r.file, 0, r.size))
	r.scanner.Buffer(make([]byte, 64*1024), MaxLineBytes+1)
	r.scanner.Split(splitLine)
	r.offset, r.state = 0, recordState{}
	r.incomplete, r.done, r.err = true, false, nil
}

func splitLine(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		if i+1 > MaxLineBytes {
			return 0, nil, ErrLineTooLarge
		}
		return i + 1, data[:i+1], nil
	}
	// A record without its optional final newline obeys the same payload bound.
	if len(data)+1 > MaxLineBytes {
		return 0, nil, ErrLineTooLarge
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func (r *Reader) Incomplete() bool { return r.incomplete }
func (r *Reader) Size() int64      { return r.size }
func (r *Reader) Offset() int64    { return r.offset }

func (r *Reader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.file.Close()
}
