//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"context"
	"fmt"
	"io"
	"strings"

	qlog "github.com/charmbracelet/log"
	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
	qoutput "github.com/natesales/q/output"
	"github.com/natesales/q/transport"
)

func postProcessReplies(replies []*dns.Msg, opts *cli.Flags) {
	for _, reply := range replies {
		if opts.TXTConcat {
			concatTXT(reply)
		}
		if opts.RoundTTLs {
			roundAnswerTTLs(reply)
		}
	}
}

func concatTXT(msg *dns.Msg) {
	for _, answer := range msg.Answer {
		txt, ok := answer.(*dns.TXT)
		if ok {
			qlog.Debugf("Concatenating TXT response: %+v", txt.Txt)
			txt.Txt = []string{strings.Join(txt.Txt, "")}
		}
	}
}

func roundAnswerTTLs(msg *dns.Msg) {
	for _, answer := range msg.Answer {
		answer.Header().Ttl -= answer.Header().Ttl % 60
	}
}

func loadPTRs(ctx context.Context, entry *qoutput.Entry, txp transport.Transport) error {
	if entry.PTRs == nil {
		entry.PTRs = make(map[string]string)
	}
	for _, reply := range entry.Replies {
		for _, rr := range reply.Answer {
			ip := addressRecordIP(rr)
			if ip == "" {
				continue
			}
			qname, err := dns.ReverseAddr(ip)
			if err != nil {
				return fmt.Errorf("reverse PTR address %s: %w", ip, err)
			}
			query := new(dns.Msg)
			query.SetQuestion(qname, dns.TypePTR)
			response, err := exchangeWithContext(ctx, txp, query)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				qlog.Warnf("error resolving PTR record: %s", err)
				continue
			}
			if response == nil {
				continue
			}
			for _, answer := range response.Answer {
				if ptr, ok := answer.(*dns.PTR); ok {
					entry.PTRs[ip] = ptr.Ptr
					break
				}
			}
		}
	}
	return nil
}

func addressRecordIP(rr dns.RR) string {
	switch record := rr.(type) {
	case *dns.A:
		return record.A.String()
	case *dns.AAAA:
		return record.AAAA.String()
	default:
		return ""
	}
}

func renderEntries(out io.Writer, opts *cli.Flags, entries []*qoutput.Entry) error {
	printer := qoutput.Printer{Out: out, Opts: opts}
	if (opts.NSID && (opts.Format == qoutput.FormatPretty || opts.Format == qoutput.FormatColumn)) || opts.NSIDOnly {
		printer.PrettyPrintNSID(entries, !opts.NSIDOnly)
	}
	if opts.NSIDOnly {
		return nil
	}

	switch opts.Format {
	case qoutput.FormatPretty:
		printer.PrintPretty(entries)
	case qoutput.FormatColumn:
		printer.PrintColumn(entries)
	case qoutput.FormatRAW:
		printer.PrintRaw(entries)
	case qoutput.FormatJSON, qoutput.FormatYAML, "yml":
		printer.PrintStructured(entries)
	default:
		return fmt.Errorf("invalid output format %s", opts.Format)
	}
	return nil
}
