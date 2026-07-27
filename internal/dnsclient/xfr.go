//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	qlog "github.com/charmbracelet/log"
	"github.com/miekg/dns"
)

type zoneTransferFunc func(context.Context, string, string, time.Duration) ([]dns.RR, error)

func runRecursiveAXFR(ctx context.Context, label, server string, timeout time.Duration, out io.Writer) error {
	root, err := recursiveAXFRRoot(label, time.Now())
	if err != nil {
		return err
	}
	return runRecursiveAXFRTo(ctx, label, server, timeout, root, out, transferZone)
}

func recursiveAXFRRoot(label string, now time.Time) (string, error) {
	component, err := portableAXFRLabel(label)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s_%s_recaxfr",
		component,
		strings.NewReplacer(" ", "-", ":", "-").Replace(now.Format(time.UnixDate)),
	)
	root, err := containedAXFRPath(".", name)
	if err != nil {
		return "", fmt.Errorf("build recursive AXFR directory: %w", err)
	}
	return root, nil
}

func runRecursiveAXFRTo(
	ctx context.Context,
	label, server string,
	timeout time.Duration,
	root string,
	out io.Writer,
	transfer zoneTransferFunc,
) error {
	if strings.TrimSpace(label) == "" {
		return fmt.Errorf("no name specified for AXFR")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("create recursive AXFR directory: %w", err)
	}

	if _, err := fmt.Fprintf(out, "Attempting recursive AXFR for %s\n", label); err != nil {
		return fmt.Errorf("write AXFR status: %w", err)
	}
	state := recursiveAXFRState{
		ctx:      ctx,
		server:   server,
		timeout:  timeout,
		root:     root,
		out:      out,
		transfer: transfer,
		queried:  make(map[string]bool),
	}
	if err := state.walk(label); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "AXFR complete, %d records saved to %s\n", state.records, root); err != nil {
		return fmt.Errorf("write AXFR status: %w", err)
	}
	return nil
}

type recursiveAXFRState struct {
	ctx      context.Context
	server   string
	timeout  time.Duration
	root     string
	out      io.Writer
	transfer zoneTransferFunc
	queried  map[string]bool
	records  int
}

func (s *recursiveAXFRState) walk(label string) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	label = dns.Fqdn(label)
	if _, err := zoneFilePath(s.root, label); err != nil {
		return err
	}
	if s.queried[label] {
		return nil
	}
	s.queried[label] = true
	if _, err := fmt.Fprintf(s.out, "AXFR %s\n", label); err != nil {
		return fmt.Errorf("write AXFR status: %w", err)
	}

	rrs, err := s.transfer(s.ctx, label, s.server, s.timeout)
	if err != nil {
		return fmt.Errorf("AXFR %s: %w", label, err)
	}
	if err := writeZoneFile(s.root, label, rrs); err != nil {
		return err
	}
	s.records += len(rrs)

	for _, rr := range rrs {
		if _, ok := rr.(*dns.NS); ok {
			if err := s.walk(rr.Header().Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeZoneFile(root, label string, rrs []dns.RR) error {
	path, err := zoneFilePath(root, label)
	if err != nil {
		return err
	}
	if len(rrs) == 0 {
		return nil
	}
	var zone strings.Builder
	for _, rr := range rrs {
		zone.WriteString(rr.String())
		zone.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(zone.String()), 0o644); err != nil {
		return fmt.Errorf("write AXFR zone file: %w", err)
	}
	return nil
}

func zoneFilePath(root, label string) (string, error) {
	component, err := portableAXFRLabel(label)
	if err != nil {
		return "", err
	}
	path, err := containedAXFRPath(root, component+".zone")
	if err != nil {
		return "", fmt.Errorf("build AXFR zone path for %q: %w", label, err)
	}
	return path, nil
}

func portableAXFRLabel(label string) (string, error) {
	if strings.TrimSpace(label) == "" {
		return "", fmt.Errorf("unsafe AXFR zone label %q", label)
	}
	if _, ok := dns.IsDomainName(label); !ok {
		return "", fmt.Errorf("unsafe AXFR zone label %q", label)
	}
	component := strings.TrimSuffix(dns.Fqdn(label), ".")
	if component == "" {
		return "!root", nil
	}
	for i := 0; i < len(component); i++ {
		if !isPortableAXFRLabelByte(component[i]) {
			return "", fmt.Errorf("unsafe AXFR zone label %q", label)
		}
	}
	if isWindowsReservedAXFRName(component) {
		return "", fmt.Errorf("unsafe AXFR zone label %q", label)
	}
	return component, nil
}

func isPortableAXFRLabelByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '.' || value == '-' || value == '_'
}

func isWindowsReservedAXFRName(component string) bool {
	firstLabel, _, _ := strings.Cut(component, ".")
	upper := strings.ToUpper(firstLabel)
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	return len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) &&
		upper[3] >= '1' && upper[3] <= '9'
}

func containedAXFRPath(root, name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return "", fmt.Errorf("unsafe AXFR path component %q", name)
	}
	cleanRoot := filepath.Clean(root)
	path := filepath.Join(cleanRoot, name)
	relative, err := filepath.Rel(cleanRoot, path)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("AXFR path %q escapes root %q", path, cleanRoot)
	}
	return path, nil
}

func transferZone(ctx context.Context, label, server string, timeout time.Duration) ([]dns.RR, error) {
	transfer := &dns.Transfer{
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}
	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(label))
	envelopes, err := transfer.In(msg, server)
	if err != nil {
		return nil, err
	}
	return collectTransferEnvelopes(ctx, label, transfer, envelopes)
}

func collectTransferEnvelopes(
	ctx context.Context,
	label string,
	transfer *dns.Transfer,
	envelopes <-chan *dns.Envelope,
) ([]dns.RR, error) {
	var records []dns.RR
	for {
		select {
		case <-ctx.Done():
			_ = transfer.Close()
			for range envelopes {
			}
			return nil, ctx.Err()
		case envelope, ok := <-envelopes:
			if !ok {
				return records, nil
			}
			if envelope.Error != nil {
				qlog.Warnf("AXFR section error (%s): %s", label, envelope.Error)
				continue
			}
			records = append(records, envelope.RR...)
		}
	}
}
