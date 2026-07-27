//go:build !flavor_tiny && !flavor_ntr

package cmd

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/akamensky/argparse"
	"github.com/nxtrace/NTrace-core/internal/dnsclient"
)

func registerDNSFlag(parser *argparse.Parser) *bool {
	return registerDNSFlagWithAvailability(parser, true)
}

func maybeRunDNSMode(rawArgs []string, stdout, stderr io.Writer) (bool, int) {
	return maybeRunDNSModeWithAvailability(true, rawArgs, stdout, stderr, runDNSClient)
}

func runDNSClient(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return dnsclient.Run(ctx, args, stdout, stderr)
}
