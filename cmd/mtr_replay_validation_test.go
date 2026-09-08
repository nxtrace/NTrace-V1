package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/internal/mtrsession"
	"github.com/nxtrace/NTrace-core/trace"
)

func TestMTRReplayHelpWithoutFile(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "--version", "-V"} {
		for _, args := range [][]string{{"--mtr-replay", flag}, {flag, "--mtr-replay"}, {"--no-color", "--mtr-replay", flag}} {
			var output, diagnostic bytes.Buffer
			handled, code := maybeRunMTRReplayMode(args, &output, &diagnostic)
			if !handled || code != 0 || output.Len() == 0 || diagnostic.Len() != 0 {
				t.Fatalf("args=%v handled=%v code=%d output=%q diagnostic=%q", args, handled, code, output.String(), diagnostic.String())
			}
		}
	}
}

func TestMTRReplayHelpLikeFilename(t *testing.T) {
	t.Chdir(t.TempDir())
	data, err := os.ReadFile(replayFixture(t, time.Now(), true))
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{"--help", "--version", "-h", "-V"} {
		if err := os.WriteFile(filename, data, 0600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"--mtr-replay=" + filename, "--json"}, {"--mtr-replay", "./" + filename, "--json"}} {
			var output, diagnostic bytes.Buffer
			handled, code := maybeRunMTRReplayMode(args, &output, &diagnostic)
			if !handled || code != 0 || !strings.Contains(output.String(), `"type":"mtr_replay"`) || diagnostic.Len() != 0 {
				t.Fatalf("args=%v code=%d output=%q diagnostic=%q", args, code, output.String(), diagnostic.String())
			}
		}
	}
}

func TestMTRReplayRejectsUnknownResponseKind(t *testing.T) {
	for _, kind := range []string{"", "future_response"} {
		file := replayFixture(t, time.Now(), true)
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var rewritten bytes.Buffer
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var record mtrsession.Record
			if err := json.Unmarshal(line, &record); err != nil {
				t.Fatal(err)
			}
			if record.Probe != nil {
				record.Probe.Response = &trace.MTRProbeResponse{Kind: kind, Marker: "!H"}
			}
			if err := json.NewEncoder(&rewritten).Encode(record); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(file, rewritten.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		var output, diagnostic bytes.Buffer
		handled, code := maybeRunMTRReplayMode([]string{"--mtr-replay", file, "--json"}, &output, &diagnostic)
		if !handled || code != 1 || output.Len() != 0 || !strings.Contains(diagnostic.String(), "response kind") {
			t.Fatalf("kind=%q code=%d output=%q diagnostic=%q", kind, code, output.String(), diagnostic.String())
		}
	}
}
