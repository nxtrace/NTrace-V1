package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/nxtrace/NTrace-core/trace"
)

func TestMTRRunContextBorrowsCaller(t *testing.T) {
	parent, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	ctx, stop := mtrRunContext(trace.Config{Context: parent})
	defer stop()
	if ctx != parent {
		t.Fatal("mode must reuse the caller's context and signal owner")
	}
	stop()
	if parent.Err() != nil {
		t.Fatal("mode cleanup canceled the caller")
	}
	cause := &mtrJSONSignal{signal: syscall.SIGTERM}
	cancel(cause)
	if context.Cause(ctx) != cause {
		t.Fatalf("cause=%v, want %v", context.Cause(ctx), cause)
	}
}

func TestMTRRunContextOwnsStandaloneCancellation(t *testing.T) {
	ctx, stop := mtrRunContext(trace.Config{})
	defer stop()
	if ctx.Err() != nil {
		t.Fatalf("unexpected initial error: %v", ctx.Err())
	}
	stop()
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatalf("cause=%v, want context.Canceled", context.Cause(ctx))
	}
}

func TestMTRRunErrorPreservesCauseAndRuntimeError(t *testing.T) {
	runtimeErr := errors.New("probe setup failed")
	for _, cause := range []error{&mtrJSONSignal{signal: os.Interrupt}, &mtrJSONSignal{signal: syscall.SIGTERM}, io.ErrClosedPipe, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			cancel(cause)
			for _, runErr := range []error{nil, context.Canceled, cause} {
				if got := mtrRunError(ctx, runErr); got != cause {
					t.Fatalf("run error=%v, result=%v, want %v", runErr, got, cause)
				}
			}
			if got := mtrRunError(ctx, runtimeErr); got != runtimeErr {
				t.Fatalf("runtime error replaced: %v", got)
			}
		})
	}
	if got := mtrRunError(t.Context(), nil); got != nil {
		t.Fatalf("successful run returned %v", got)
	}
}

func TestMTRReportInterruptionKeepsFinalOutput(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		for _, result := range []string{"cause", "canceled", "nil", "runtime-error", "no-data"} {
			t.Run(sig.String()+"/"+result, func(t *testing.T) {
				parent, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				cause := &mtrJSONSignal{signal: sig}
				runtimeErr := errors.New("probe setup failed")
				oldRun := runMTRReportFn
				t.Cleanup(func() { runMTRReportFn = oldRun })
				runMTRReportFn = func(ctx context.Context, _ trace.Method, _ trace.Config, _ trace.MTROptions, snapshot trace.MTROnSnapshot) error {
					if ctx != parent {
						t.Fatal("report installed another context instead of borrowing its caller")
					}
					if result != "no-data" {
						snapshot(1, []trace.MTRHopStat{{TTL: 1, IP: "127.0.0.1", Snt: 1, Received: 1}})
					}
					cancel(cause)
					switch result {
					case "canceled":
						return ctx.Err()
					case "nil":
						return nil
					case "runtime-error":
						return runtimeErr
					default:
						return context.Cause(ctx)
					}
				}
				output, err := os.Create(filepath.Join(t.TempDir(), "report.txt"))
				if err != nil {
					t.Fatal(err)
				}
				oldStdout := os.Stdout
				t.Cleanup(func() { os.Stdout = oldStdout; _ = output.Close() })
				os.Stdout = output
				err = runMTRReport(trace.ICMPTrace, trace.Config{Context: parent}, 1, 1, "", "", false, false, nil)
				os.Stdout = oldStdout
				text, readErr := os.ReadFile(output.Name())
				if readErr != nil {
					t.Fatal(readErr)
				}
				if result == "runtime-error" {
					if err != runtimeErr || len(text) != 0 {
						t.Fatalf("error=%v output=%q", err, text)
					}
					return
				}
				wantOutput := "127.0.0.1"
				if result == "no-data" {
					wantOutput = "No data collected."
				}
				if err != cause || !strings.Contains(string(text), wantOutput) {
					t.Fatalf("error=%v, want %v; output=%q", err, cause, text)
				}
			})
		}
	}
}
