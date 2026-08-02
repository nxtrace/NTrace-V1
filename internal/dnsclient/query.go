//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"fmt"
	"net"

	qlog "github.com/charmbracelet/log"
	"github.com/miekg/dns"
)

const maxDNSQueryID = 1<<16 - 1

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
	queryID, err := normalizedQueryID(opts.ID)
	if err != nil {
		return dns.Msg{}, err
	}
	request.Id = queryID
	request.Authoritative = opts.AuthoritativeAnswer
	request.AuthenticatedData = opts.AuthenticData
	request.CheckingDisabled = opts.CheckingDisabled
	request.RecursionDesired = opts.RecursionDesired
	request.RecursionAvailable = opts.RecursionAvailable
	request.Zero = opts.Zero
	request.Truncated = opts.Truncated

	request.Question = []dns.Question{{
		Name:   dns.Fqdn(opts.Name),
		Qtype:  rrType,
		Qclass: opts.Class,
	}}
	opt, err := buildEDNS(request, config)
	if err != nil {
		return dns.Msg{}, err
	}
	if opt != nil && opts.EDNS {
		request.Extra = append(request.Extra, opt)
	}
	return request, nil
}

func normalizedQueryID(value int) (uint16, error) {
	if value == -1 {
		return dns.Id(), nil
	}
	if value < 0 || value > maxDNSQueryID {
		return 0, fmt.Errorf("query ID must be -1 or between 0 and %d (got %d)", maxDNSQueryID, value)
	}
	return uint16(value), nil
}

func buildEDNS(request dns.Msg, config Config) (*dns.OPT, error) {
	opts := config.Flags
	// Match q v0.19.12: validate requested EDNS options even when EDNS is
	// disabled, then omit the completed OPT record in buildQuery.
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
	var padding *dns.EDNS0_PADDING
	if opts.Pad {
		padding = &dns.EDNS0_PADDING{}
		opt.Option = append(opt.Option, padding)
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
	if padding != nil {
		request.Extra = append(request.Extra, opt)
		messageLength := request.Len()
		paddingLength := 128 - messageLength%128
		if messageLength+paddingLength > int(opt.UDPSize()) {
			paddingLength = int(opt.UDPSize()) - messageLength
			if paddingLength < 0 {
				paddingLength = 0
			}
		}
		qlog.Debugf("Padding with %d bytes", paddingLength)
		padding.Padding = make([]byte, paddingLength)
	}
	return opt, nil
}

func parseClientSubnet(value string) (*dns.EDNS0_SUBNET, error) {
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("parsing subnet %s: %w", value, err)
	}
	mask, _ := network.Mask.Size()
	qlog.Debugf("EDNS0 client subnet %s/%d", network.IP, mask)
	family := uint16(1)
	if network.IP.To4() == nil {
		family = 2
	}
	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Address:       network.IP,
		Family:        family,
		SourceNetmask: uint8(mask),
	}, nil
}
