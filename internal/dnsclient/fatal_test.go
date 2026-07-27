//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	fatalHelperEnv         = "NEXTTRACE_DNS_FATAL_HELPER"
	dnsCryptFatalHelperEnv = "NEXTTRACE_DNSCRYPT_FATAL_HELPER"
)

func TestOutputFatalPathRunsInSubprocess(t *testing.T) {
	if os.Getenv(fatalHelperEnv) == "1" {
		code := Run(context.Background(), []string{
			"--server=" + os.Getenv("NEXTTRACE_DNS_FATAL_SERVER"),
			"--qname=example.com",
			"--type=A",
			"--format=raw",
			"--timeout=1s",
		}, errorWriter{}, os.Stderr)
		os.Exit(code)
	}

	server := startTestDNSServer(t, "udp")
	command := exec.Command(os.Args[0], "-test.run=^TestOutputFatalPathRunsInSubprocess$")
	command.Env = append(os.Environ(),
		fatalHelperEnv+"=1",
		"NEXTTRACE_DNS_FATAL_SERVER="+server,
		"HOME="+t.TempDir(),
		"NO_COLOR=1",
		"SSLKEYLOGFILE=",
	)
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
		t.Fatalf("helper error = %v, output=%q", err, output)
	}
	if !strings.Contains(string(output), "forced writer failure") {
		t.Fatalf("helper output = %q", output)
	}
}

func TestDNSCryptFatalPathRunsInSubprocess(t *testing.T) {
	if os.Getenv(dnsCryptFatalHelperEnv) == "1" {
		code := Run(context.Background(), []string{
			"--server=dnscrypt://" + os.Getenv("NEXTTRACE_DNSCRYPT_FATAL_SERVER"),
			"--dnscrypt-key=" + strings.Repeat("00", 32),
			"--dnscrypt-provider=2.dnscrypt-cert.example",
			"--qname=example.com",
			"--type=A",
			"--timeout=1s",
		}, io.Discard, os.Stderr)
		os.Exit(code)
	}

	server := startTestDNSServer(t, "udp")
	command := exec.Command(os.Args[0], "-test.run=^TestDNSCryptFatalPathRunsInSubprocess$")
	command.Env = append(os.Environ(),
		dnsCryptFatalHelperEnv+"=1",
		"NEXTTRACE_DNSCRYPT_FATAL_SERVER="+server,
		"HOME="+t.TempDir(),
		"NO_COLOR=1",
		"SSLKEYLOGFILE=",
	)
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
		t.Fatalf("helper error = %v, output=%q", err, output)
	}
	if !strings.Contains(string(output), "failed to dial DNSCrypt server") {
		t.Fatalf("helper output = %q", output)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced writer failure")
}

var _ io.Writer = errorWriter{}
