//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"fmt"
	"net"

	qlog "github.com/charmbracelet/log"
	"github.com/miekg/dns"
)

// BuildQueries constructs one q-compatible DNS message per requested RR type.
func BuildQueries(config Config) ([]dns.Msg, error) {
	queries := make([]dns.Msg, 0, len(config.RRTypes))
	for _, rrType := range config.RRTypes {
		query, err := buildQuery(config, rrType)
		if err != nil {
			return nil, err
		}
		queries = append(queries, query)
	}
	return queries, nil
}

func buildQuery(config Config, rrType uint16) (dns.Msg, error) {
	opts := config.Flags
	request := dns.Msg{}
	if opts.ID == -1 {
		request.Id = dns.Id()
	} else {
		request.Id = uint16(opts.ID)
	}
	request.Authoritative = opts.AuthoritativeAnswer
	request.AuthenticatedData = opts.AuthenticData
	request.CheckingDisabled = opts.CheckingDisabled
	request.RecursionDesired = opts.RecursionDesired
	request.RecursionAvailable = opts.RecursionAvailable
	request.Zero = opts.Zero
	request.Truncated = opts.Truncated

	opt, err := buildEDNS(request, config)
	if err != nil {
		return dns.Msg{}, err
	}
	if opt != nil && opts.EDNS {
		request.Extra = append(request.Extra, opt)
	}
	request.Question = []dns.Question{{
		Name:   dns.Fqdn(opts.Name),
		Qtype:  rrType,
		Qclass: opts.Class,
	}}
	return request, nil
}

func buildEDNS(request dns.Msg, config Config) (*dns.OPT, error) {
	opts := config.Flags
	if !opts.EDNS && !opts.DNSSEC && !opts.NSID && !opts.Pad && opts.ClientSubnet == "" && opts.Cookie == "" {
		return nil, nil
	}
	opt := &dns.OPT{Hdr: dns.RR_Header{
		Name:   ".",
		Class:  opts.UDPBuffer,
		Rrtype: dns.TypeOPT,
	}}
	if opts.DNSSEC {
		opt.SetDo()
	}
	if opts.NSID {
		opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
	}
	if opts.Pad {
		messageLength := request.Len()
		paddingLength := 128 - messageLength%128
		if messageLength+paddingLength > int(opt.UDPSize()) {
			paddingLength = int(opt.UDPSize()) - messageLength
			if paddingLength < 0 {
				paddingLength = 0
			}
		}
		qlog.Debugf("Padding with %d bytes", paddingLength)
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, paddingLength)})
	}
	if opts.ClientSubnet != "" {
		subnet, err := parseClientSubnet(opts.ClientSubnet)
		if err != nil {
			return nil, err
		}
		opt.Option = append(opt.Option, subnet)
	}
	if opts.Cookie != "" {
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
			Code:   dns.EDNS0COOKIE,
			Cookie: opts.Cookie,
		})
	}
	return opt, nil
}

func parseClientSubnet(value string) (*dns.EDNS0_SUBNET, error) {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("parsing subnet %s: %w", value, err)
	}
	mask, _ := network.Mask.Size()
	qlog.Debugf("EDNS0 client subnet %s/%d", ip, mask)
	family := uint16(1)
	if ip.To4() == nil {
		family = 2
	}
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Address:       ip,
		Family:        family,
		SourceNetmask: uint8(mask),
	}, nil
}
