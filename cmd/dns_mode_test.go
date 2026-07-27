package cmd

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/akamensky/argparse"
)

func TestMaybeRunDNSModePassesArgumentsAfterLeadingMarkerUnchanged(t *testing.T) {
	want := []string{"example.com", "MX", "@1.1.1.1", "--format=json"}
	var got []string
	runner := func(args []string, _, _ io.Writer) int {
		got = append([]string(nil), args...)
		return 7
	}
	var stdout, stderr bytes.Buffer
	handled, code := maybeRunDNSModeWithAvailability(true, append([]string{"--dns"}, want...), &stdout, &stderr, runner)
	if !handled || code != 7 {
		t.Fatalf("handled/code = %v/%d, want true/7", handled, code)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
}

func TestMaybeRunDNSModeOnlyRecognizesFirstArgument(t *testing.T) {
	for _, args := range [][]string{{"example.com", "--dns"}, {"--", "--dns"}, {"--dns=true"}} {
		handled, _ := maybeRunDNSModeWithAvailability(true, args, io.Discard, io.Discard, func([]string, io.Writer, io.Writer) int {
			t.Fatal("runner should not be called")
			return 0
		})
		if handled {
			t.Fatalf("args %q unexpectedly handled", args)
		}
	}
}

func TestMaybeRunDNSModeDisabledReportsUnavailable(t *testing.T) {
	for _, args := range [][]string{
		{"-l", "example.com"},
		{"example.com", "--dns"},
	} {
		var stderr bytes.Buffer
		handled, code := maybeRunDNSModeWithAvailability(false, args, io.Discard, &stderr, nil)
		if !handled || code != 1 {
			t.Fatalf("args %q: handled/code = %v/%d, want true/1", args, handled, code)
		}
		if !strings.Contains(stderr.String(), "not available") {
			t.Fatalf("args %q: stderr = %q", args, stderr.String())
		}
	}
}

func TestMaybeRunDNSModeDisabledIgnoresMarkerAfterDoubleDash(t *testing.T) {
	handled, code := maybeRunDNSModeWithAvailability(false, []string{"example.com", "--", "--dns"}, io.Discard, io.Discard, nil)
	if handled || code != 0 {
		t.Fatalf("handled/code = %v/%d, want false/0", handled, code)
	}
}

func TestRegisterDNSFlagAvailability(t *testing.T) {
	full := argparse.NewParser("nexttrace", "")
	registerDNSFlagWithAvailability(full, true)
	if usage := full.Usage(nil); !strings.Contains(usage, "--dns") || !strings.Contains(usage, "-l") {
		t.Fatalf("full usage missing DNS entry:\n%s", usage)
	}

	disabled := argparse.NewParser("ntr", "")
	registerDNSFlagWithAvailability(disabled, false)
	if usage := disabled.Usage(nil); strings.Contains(usage, "--dns") {
		t.Fatalf("disabled usage contains DNS entry:\n%s", usage)
	}
}
