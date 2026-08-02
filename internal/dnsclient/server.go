//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	qlog "github.com/charmbracelet/log"
	"github.com/jedisct1/go-dnsstamps"
	qtransport "github.com/natesales/q/transport"
)

var serverSchemePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// ParsedServer is the normalized server description consumed by the q
// transport adapter. Address matches the server string q passes to its public
// transport implementations.
type ParsedServer struct {
	Original      string
	Address       string
	TransportType qtransport.Type
	Scheme        string
	Host          string
	Port          string
	Path          string
	ServerName    string
	FromStamp     bool
}

// ParseServer normalizes q-compatible server forms, including DNS stamps,
// protocol URLs, host names, IPv4 addresses, and scoped IPv6 addresses.
func ParseServer(server string) (ParsedServer, error) {
	parsed := ParsedServer{Original: server}
	if server == "" {
		return parsed, fmt.Errorf("DNS server is empty")
	}

	normalized := server
	if strings.HasPrefix(server, "sdns://") {
		stamp, err := dnsstamps.NewServerStampFromString(server)
		if err != nil {
			return parsed, fmt.Errorf("parse DNS stamp: %w", err)
		}
		parsed.FromStamp = true
		parsed.ServerName = stamp.ProviderName
		if stamp.Proto == dnsstamps.StampProtoTypeDNSCrypt {
			parsed.Address = server
			parsed.TransportType = qtransport.TypeDNSCrypt
			parsed.Scheme = "sdns"
			parsed.Host, parsed.Port = splitStampAddress(stamp.ServerAddrStr)
			return parsed, nil
		}

		stampURL, err := dnsStampURL(stamp)
		if err != nil {
			return parsed, err
		}
		normalized = stampURL
	}

	uriEncodedZone := serverSchemePattern.MatchString(normalized)
	if !uriEncodedZone {
		normalized = "plain://" + bracketBareIPv6(normalized)
	}

	withoutZone, zone, err := removeIPv6Zone(normalized, uriEncodedZone)
	if err != nil {
		return parsed, err
	}
	if zone != "" {
		qlog.Debugf("Removed IPv6 scope ID %s from server %s", "%"+zone, withoutZone)
	}
	withoutZone = bracketURLIPv6(withoutZone)

	u, err := url.Parse(withoutZone)
	if err != nil {
		return parsed, fmt.Errorf("parse DNS server %q: %w", server, err)
	}
	if u.Host == "" {
		return parsed, fmt.Errorf("DNS server %q has no host", server)
	}

	transportType, err := parseTransportType(u.Scheme)
	if err != nil {
		return parsed, err
	}
	if u.User != nil && transportType != qtransport.TypeHTTP {
		return parsed, fmt.Errorf("DNS server %q must not contain user information", server)
	}
	host := u.Hostname()
	if host == "" {
		return parsed, fmt.Errorf("DNS server %q has no host", server)
	}
	if zone != "" {
		if net.ParseIP(host) == nil || !strings.Contains(host, ":") {
			return parsed, fmt.Errorf("DNS server %q has a zone on a non-IPv6 host", server)
		}
		host += "%" + zone
	}

	port := u.Port()
	if port == "" {
		port = defaultServerPort(transportType, u.Scheme)
	}
	if port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return parsed, fmt.Errorf("invalid DNS server port %q: %w", port, err)
		}
	}

	if transportType != qtransport.TypeHTTP && (u.Path != "" || u.RawQuery != "" || u.Fragment != "") {
		return parsed, fmt.Errorf("%s DNS server must not contain a path, query, or fragment", transportType)
	}
	if transportType == qtransport.TypeHTTP && u.Path == "" {
		u.Path = "/dns-query"
	}

	parsed.TransportType = transportType
	parsed.Scheme = u.Scheme
	parsed.Host = host
	parsed.Port = port
	parsed.Path = u.EscapedPath()
	if parsed.ServerName == "" {
		parsed.ServerName = host
	}

	if transportType == qtransport.TypeHTTP {
		u.Host = net.JoinHostPort(host, port)
		parsed.Address = u.String()
	} else if port == "" {
		parsed.Address = host
	} else {
		parsed.Address = net.JoinHostPort(host, port)
	}

	return parsed, nil
}

func splitStampAddress(address string) (string, string) {
	host, port, err := net.SplitHostPort(address)
	if err == nil {
		return host, port
	}
	return address, ""
}

func dnsStampURL(stamp dnsstamps.ServerStamp) (string, error) {
	u := url.URL{Host: stamp.ProviderName, Path: stamp.Path}
	switch stamp.Proto {
	case dnsstamps.StampProtoTypePlain:
		u.Scheme = string(qtransport.TypePlain)
	case dnsstamps.StampProtoTypeTLS:
		u.Scheme = string(qtransport.TypeTLS)
	case dnsstamps.StampProtoTypeDoH:
		u.Scheme = "https"
	default:
		return "", fmt.Errorf("unsupported protocol %s in DNS stamp", stamp.Proto.String())
	}
	return u.String(), nil
}

func parseTransportType(scheme string) (qtransport.Type, error) {
	if scheme == "https" {
		return qtransport.TypeHTTP, nil
	}
	t := qtransport.Type(scheme)
	for _, supported := range qtransport.Types {
		if t == supported {
			return t, nil
		}
	}
	return "", fmt.Errorf("unsupported DNS transport %q (expected one of %v or https)", scheme, qtransport.Types)
}

func defaultServerPort(transportType qtransport.Type, scheme string) string {
	switch transportType {
	case qtransport.TypePlain, qtransport.TypeTCP:
		return "53"
	case qtransport.TypeTLS, qtransport.TypeQUIC:
		return "853"
	case qtransport.TypeHTTP:
		if scheme == "https" {
			return "443"
		}
		return "80"
	default:
		return ""
	}
}

func bracketBareIPv6(authority string) string {
	if strings.HasPrefix(authority, "[") {
		return authority
	}
	host := authority
	if percent := strings.LastIndex(host, "%"); percent >= 0 {
		host = host[:percent]
	}
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		return "[" + authority + "]"
	}
	return authority
}

func bracketURLIPv6(serverURL string) string {
	separator := strings.Index(serverURL, "://")
	if separator < 0 {
		return serverURL
	}
	start := separator + 3
	rest := serverURL[start:]
	end := len(rest)
	if delimiter := strings.IndexAny(rest, "/?#"); delimiter >= 0 {
		end = delimiter
	}
	authority := rest[:end]
	if strings.HasPrefix(authority, "[") {
		return serverURL
	}
	host := authority
	if net.ParseIP(host) == nil || !strings.Contains(host, ":") {
		return serverURL
	}
	return serverURL[:start] + "[" + authority + "]" + rest[end:]
}

func removeIPv6Zone(serverURL string, uriEncodedZone bool) (string, string, error) {
	separator := strings.Index(serverURL, "://")
	if separator < 0 {
		return serverURL, "", nil
	}
	start := separator + 3
	rest := serverURL[start:]
	end := len(rest)
	if delimiter := strings.IndexAny(rest, "/?#"); delimiter >= 0 {
		end = delimiter
	}
	authority := rest[:end]
	hostStart := strings.LastIndex(authority, "@") + 1
	hostPort := authority[hostStart:]

	var address, encodedZone string
	var zoneStart, zoneEnd int
	if strings.HasPrefix(hostPort, "[") {
		closeBracket := strings.Index(hostPort, "]")
		if closeBracket < 0 {
			return serverURL, "", nil
		}
		host := hostPort[1:closeBracket]
		percent := strings.Index(host, "%")
		if percent < 0 {
			return serverURL, "", nil
		}
		address = host[:percent]
		encodedZone = host[percent+1:]
		zoneStart = hostStart + 1 + percent
		zoneEnd = hostStart + closeBracket
	} else {
		percent := strings.Index(hostPort, "%")
		if percent < 0 {
			return serverURL, "", nil
		}
		address = hostPort[:percent]
		if net.ParseIP(address) == nil || !strings.Contains(address, ":") {
			return serverURL, "", nil
		}
		encodedZone = hostPort[percent+1:]
		zoneStart = hostStart + percent
		zoneEnd = len(authority)
	}
	if net.ParseIP(address) == nil || !strings.Contains(address, ":") {
		return "", "", fmt.Errorf("DNS server %q has a zone on a non-IPv6 host", serverURL)
	}
	if uriEncodedZone {
		encodedZone = strings.TrimPrefix(encodedZone, "25")
	}
	zone, err := url.PathUnescape(encodedZone)
	if err != nil {
		return "", "", fmt.Errorf("invalid IPv6 zone in DNS server %q: %w", serverURL, err)
	}
	if zone == "" || strings.ContainsAny(zone, "%[]:/?#") || strings.IndexFunc(zone, unicode.IsControl) >= 0 {
		return "", "", fmt.Errorf("invalid IPv6 zone in DNS server %q", serverURL)
	}
	authority = authority[:zoneStart] + authority[zoneEnd:]
	return serverURL[:start] + authority + rest[end:], zone, nil
}
