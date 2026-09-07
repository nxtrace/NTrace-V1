package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDoctorRejectsOtherModesBeforeInitialization(t *testing.T) {
	for _, flag := range []string{"--json", "--raw", "--mtr", "--report", "--wide", "--mtr-columns", "--traceroute", "--speed", "--dns", "--mtu", "--deploy", "--init", "--setup-api-v4-token", "--psize", "--output", "--from"} {
		option := []string{flag}
		if doctorValueOption(strings.TrimLeft(flag, "-")) {
			option = append(option, "1")
		}
		for _, args := range [][]string{append(append([]string{}, option...), "--doctor", "127.0.0.1"), append([]string{"--doctor", "127.0.0.1"}, option...)} {
			var out, err bytes.Buffer
			handled, code := maybeRunDoctorMode(args, &out, &err)
			if !handled || code != 2 || out.Len() != 0 || err.Len() == 0 {
				t.Fatalf("%v: handled=%v code=%d out=%q err=%q", args, handled, code, out.String(), err.String())
			}
		}
	}
}

func TestDoctorHelpAndArgumentBoundaries(t *testing.T) {
	for _, args := range [][]string{{"--doctor", "--help"}, {"--help", "--doctor"}, {"127.0.0.1", "--doctor", "--help"}} {
		var out, err bytes.Buffer
		handled, code := maybeRunDoctorMode(args, &out, &err)
		if !handled || code != 0 || !strings.Contains(out.String(), "--doctor") || err.Len() != 0 {
			t.Fatalf("%v: %v %d %q", args, handled, code, err.String())
		}
	}
	for _, args := range [][]string{{"--", "--doctor"}, {"--source", "--doctor", "127.0.0.1"}, {"--deploy-token", "--doctor", "--deploy"}, {"--file", "--doctor"}, {"--output", "--doctor", "127.0.0.1"}} {
		var out, err bytes.Buffer
		handled, _ := maybeRunDoctorMode(args, &out, &err)
		if handled {
			t.Fatalf("mistook positional/value for mode: %v", args)
		}
	}
	for _, args := range [][]string{{"--doctor"}, {"--doctor", "https://user:secret@example.com/token"}, {"--doctor", "127.0.0.1", "--timeout", "0"}, {"--doctor", "127.0.0.1", "-4", "-6"}, {"--doctor", "127.0.0.1", "-T", "-U"}, {"--doctor", "127.0.0.1", "--port", "80"}} {
		var out, err bytes.Buffer
		_, code := maybeRunDoctorMode(args, &out, &err)
		if code != 2 || strings.Contains(err.String(), "secret") || out.Len() != 0 {
			t.Fatalf("bad validation %v: %d %q", args, code, err.String())
		}
	}
}

// Environment variables are read during package initialization, so exercising
// an already running test process would miss the original debug disclosure.
func TestDoctorProcessDoesNotDiscloseCredentials(t *testing.T) {
	if os.Getenv("NTRACE_DOCTOR_TEST_PROCESS") == "1" {
		_, code := maybeRunDoctorMode([]string{"--doctor", "--help"}, os.Stdout, os.Stderr)
		os.Exit(code)
	}
	c := exec.Command(os.Args[0], "-test.run=^TestDoctorProcessDoesNotDiscloseCredentials$")
	c.Env = append(os.Environ(), "NTRACE_DOCTOR_TEST_PROCESS=1", "NEXTTRACE_DEBUG=1",
		"NEXTTRACE_TOKEN=doctor-test-secret-1", "NEXTTRACE_DEPLOY_TOKEN=doctor-test-secret-2",
		"GLOBALPING_TOKEN=doctor-test-secret-3", "NEXTTRACE_API_V4_TOKEN=doctor-test-secret-4",
		"NEXTTRACE_PROXY=http://doctor-test-user:doctor-test-secret-5@127.0.0.1:9")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	if strings.Contains(string(out), "doctor-test-secret") || strings.Contains(string(out), "doctor-test-user") {
		t.Fatal("credential leaked during package initialization")
	}
	if !strings.Contains(string(out), "--doctor") {
		t.Fatal("doctor did not run")
	}
}
