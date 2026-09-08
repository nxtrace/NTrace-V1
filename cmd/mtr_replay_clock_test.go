package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/internal/mtrsession"
)

func TestMTRReplayHistorySurvivesWallClockJump(t *testing.T) {
	for _, jump := range []time.Duration{-10 * time.Minute, 10 * time.Minute} {
		t.Run(jump.String(), func(t *testing.T) {
			start := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
			file := replayFixture(t, start, true)
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
				var record mtrsession.Record
				if err := json.Unmarshal(line, &record); err != nil {
					t.Fatal(err)
				}
				if record.Probe != nil {
					age := int64(20 * time.Millisecond)
					record.ProbeAgeNS = &age
					record.Timestamp = record.Timestamp.Add(jump)
				}
				if err := json.NewEncoder(&output).Encode(record); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(file, output.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := mtrsession.OpenReader(file)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			final, err := readMTRReplay(t.Context(), r, time.Duration(1<<63-1))
			if err != nil {
				t.Fatal(err)
			}
			history := final.history.Snapshot(start.Add(final.cursor))
			want := start.Add(4*time.Second - 20*time.Millisecond)
			if len(history) != 1 || len(history[0].Samples) != 1 || !history[0].Samples[0].At.Equal(want) {
				t.Fatalf("history after wall clock jump %s: %+v; want one sample at %s", jump, history, want)
			}
		})
	}
}
