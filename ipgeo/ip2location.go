package ipgeo

import (
	"github.com/ip2location/ip2location-io-go/ip2locationio"
	"github.com/xgadget-lab/nexttrace/util"
	"time"
)

func IP2Location(ip string, timeout time.Duration, _ string, _ bool) (*IPGeoData, error) {
	config, err := ip2locationio.OpenConfiguration(token.ip2location)

	if err != nil {
		return nil, err
	}
	ipl, err := ip2locationio.OpenIPGeolocation(config)

	if err != nil {
		return nil, err
	}

	res, err := ipl.LookUp(ip, "")

	if err != nil {
		return nil, err
	}

	country := res.CountryName
	prov := res.RegionName
	city := res.CityName
	district := ""
	if util.StringInSlice(res.CountryCode, []string{"TW", "MO", "HK"}) {
		district = prov + " " + city
		city = res.CountryName
		prov = ""
		country = "China"
	}

	isp := res.Isp
	domain := res.Domain

	anycast := false
	if res.AddressType == "Anycast" {
		country = "ANYCAST"
		prov = "ANYCAST"
		city = ""
		anycast = true
	}

	owner := ""
	asnumber := res.Asn

	lat := res.Latitude
	lng := res.Longitude
	if anycast {
		lat, lng = 0, 0
	}

	return &IPGeoData{
		Asnumber: asnumber,
		Country:  country,
		City:     city,
		Prov:     prov,
		District: district,
		Owner:    owner,
		Isp:      isp,
		Domain:   domain,
		Lat:      lat,
		Lng:      lng,
	}, nil
}
