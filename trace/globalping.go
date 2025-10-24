package trace

import (
	"fmt"
	"math"
	"net"
	"time"

	"github.com/jsdelivr/globalping-cli/globalping"
	_config "github.com/nxtrace/NTrace-core/config"
	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/util"
)

type GlobalpingOptions struct {
	Target  string
	From    string
	IPv4    bool
	IPv6    bool
	TCP     bool
	UDP     bool
	Port    int
	Packets int

	DisableMaptrace bool
	DataOrigin      string

	TablePrint   bool
	ClassicPrint bool
	RawPrint     bool
	JSONPrint    bool
}

func GlobalpingTraceroute(opts *GlobalpingOptions, config *Config) (*Result, *globalping.Measurement, error) {
	c := globalping.Config{
		UserAgent: "NextTrace/" + _config.Version,
	}
	if util.GlobalpingToken != "" {
		c.AuthToken = &globalping.Token{
			AccessToken: util.GlobalpingToken,
			Expiry:      time.Now().Add(math.MaxInt64),
		}
	}
	client := globalping.NewClient(c)

	o := &globalping.MeasurementCreate{
		Type:   "mtr",
		Target: opts.Target,
		Limit:  1,
		Locations: []globalping.Locations{
			{
				Magic: opts.From,
			},
		},
		Options: &globalping.MeasurementOptions{
			Port:    uint16(opts.Port),
			Packets: opts.Packets,
		},
	}

	if opts.TCP {
		o.Options.Protocol = "TCP"
	} else if opts.UDP {
		o.Options.Protocol = "UDP"
	} else {
		o.Options.Protocol = "ICMP"
	}

	if opts.IPv4 {
		o.Options.IPVersion = globalping.IPVersion4
	} else if opts.IPv6 {
		o.Options.IPVersion = globalping.IPVersion6
	}

	res, err := client.CreateMeasurement(o)
	if err != nil {
		return nil, nil, err
	}

	measurement, err := client.AwaitMeasurement(res.ID)
	if err != nil {
		return nil, nil, err
	}

	if measurement.Status != globalping.StatusFinished {
		return nil, nil, fmt.Errorf("measurement did not complete successfully: %s", measurement.Status)
	}

	gpHops, err := globalping.DecodeMTRHops(measurement.Results[0].Result.HopsRaw)
	if err != nil {
		return nil, nil, err
	}

	result := &Result{}
	geoMap := map[string]*ipgeo.IPGeoData{}
	maxTimings := 1

	for i := range gpHops {
		maxTimings = max(maxTimings, len(gpHops[i].Timings))
	}
	for i := range gpHops {
		hops := make([]Hop, 0, maxTimings)
		for j := range maxTimings {
			var timing *globalping.MTRTiming
			if j < len(gpHops[i].Timings) {
				timing = &gpHops[i].Timings[j]
			}
			hop := mapGlobalpingHop(i+1, &gpHops[i], timing, geoMap, config)
			hops = append(hops, hop)
		}
		result.Hops = append(result.Hops, hops)
	}

	return result, measurement, nil
}

func mapGlobalpingHop(ttl int, gpHop *globalping.MTRHop, timing *globalping.MTRTiming, geoMap map[string]*ipgeo.IPGeoData, config *Config) Hop {
	hop := Hop{
		Hostname: gpHop.ResolvedHostname,
		TTL:      ttl,
		Lang:     config.Lang,
	}

	if gpHop.ResolvedAddress != "" {
		hop.Address = &net.IPAddr{
			IP: net.ParseIP(gpHop.ResolvedAddress),
		}
		if geo, ok := geoMap[gpHop.ResolvedAddress]; ok {
			hop.Geo = geo
		} else {
			hop.fetchIPData(*config)
			geoMap[gpHop.ResolvedAddress] = hop.Geo
		}
	}

	if timing == nil {
		return hop
	}

	hop.Success = true
	hop.RTT = time.Duration(timing.RTT * float64(time.Millisecond))

	return hop
}

func GlobalpingFormatLocation(m *globalping.ProbeMeasurement) string {
	state := ""
	if m.Probe.State != "" {
		state = " (" + m.Probe.State + ")"
	}
	return m.Probe.City + state + ", " +
		m.Probe.Country + ", " +
		m.Probe.Continent + ", " +
		m.Probe.Network + " " +
		"(AS" + fmt.Sprint(m.Probe.ASN) + ")"
}
