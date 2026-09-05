package ipgeo

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nxtrace/NTrace-core/dn42"
)

var countryOrAreaNameByLtdCode = func() map[string]string {
	regionName := []string{"United States", "Afghanistan", "Åland Islands", "Albania", "Algeria", "American Samoa", "Andorra", "Angola", "Anguilla", "Antarctica", "Antigua and Barbuda", "Argentina", "Armenia", "Aruba", "Australia", "Austria", "Azerbaijan", "Bahamas", "Bahrain", " Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin", "Bermuda", "Bhutan", "Bolivia", "Bosnia and Herzegovina", "Botswana", "Bouvet Island", "Brazil", "British Indian Ocean Territory", "Brunei", "Bulgaria", "Burkina Faso", "Burundi", "Cambodia", "Cameroon", "Canada ", "Cape Verde", "Cayman Islands", "Central Africa", "Chad", "Chile", "China", "Christmas Island", "Cocos (Keeling) Islands", "Colombia", "Comoros", "Congo (Brazzaville)", "DRC", "Cook Islands", "Costa Rica", "Cote d'Ivoire", "Croatia", "Cuba", "Cyprus", "Czech Republic", " Denmark", "Djibouti", "Dominica", "Dominica", "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", "Ethiopia", "Falkland Islands (Malvinas)", "Faroe Islands", "Fiji", "Finland", "France", "French Guiana", "French Polynesia", " French Southern Territories", "Gabon", "Gambia", "Georgia", "Germany", "Ghana", "Gibraltar", "Greece", "Greenland", "Grenada", "Guadeloupe", "Guam", "Guatemala", "Guernsey", "Guinea", "Guinea-Bissau", "Guyana", "Haiti", "Heard and McDonald Islands", "Vatican", "Honduras", "Hong Kong", "Hungary", "Iceland", "India", "Indonesia", "Iran", "Iraq", "Ireland", "British Isles of Man", "Israel", "Italy", "Jamaica", "Japan", "Jersey", "Jordan", "Kazakhstan", "Kenya", "Kiribati", "North Korea", "South Korea", " Kuwait", "Kyrgyzstan", "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libya", "Liechtenstein", "Lithuania", "Luxembourg", "Macao", "FYROM", "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", "Malta", " Marshall Islands", "Martinique", "Mauritania", "Mauritius", "Mayotte", "Mexico", "Micronesia (Federated States of)", "Moldova", "Monaco", "Mongolia", "Montenegro", "Montserrat", "Morocco", "Mozambique", "Myanmar", "Namibia", "Nauru", "Nepal", "Netherlands", "Netherlands Antilles", "New Caledonia", "New Zealand", "Nicaragua", "Niger", "Nigeria", "Niue", "Norfolk Island", "Northern Mariana", "Norway", "Oman", "Pakistan", "Palau", "Palestine", "Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines", "Pitcairn", "Poland", "Portugal", "Puerto Rico", "Qatar", "Reunion", "Romania", "Russian Federation", "Rwanda", "St. Helena", "St. Kitts and Nevis", "St. Lucia", "St. Pierre and Miquelon", "St. Vincent and the Grenadines", "Samoa", "San Marino", "Sao Tome and Principe", "Saudi Arabia", "Senegal", "Serbia", "Seychelles", "Sierra Leone", "Singapore", "Slovakia", "Slovenia", "Solomon Islands", "Somalia", "South Africa", "South Georgia and South Sandwich Islands", "Spain", "Sri Lanka", "Sudan", "Suriname", "Svalbard and Jan Mayen Islands", "Swaziland", "Sweden ", "Switzerland", "Syria", "Taiwan", "Tajikistan", "Tanzania", "Thailand", "Timor-Leste", "Togo", "Tokelau", "Tonga", "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Turks and Caicos Islands", "Tuvalu", "Uganda", "Ukraine", "United Arab Emirates", " United Kingdom", "U.S. Minor Outlying Islands", "Uruguay", "Uzbekistan", "Vanuatu", "Venezuela", "Vietnam", "British Virgin Islands", "U.S. Virgin Islands", "Wallis and Futuna", "Western Sahara", "Yemen", "Zambia", "Zimbabwe"}
	regionCode := []string{"us", "af", "ax", "al", "dz", "as", "ad", "ao", "ai", "aq", "ag", "ar", "am", "aw", "au", "at", "az", "bs", "bh", "bd", "bb", "by", "be", "bz", "bj", "bm", "bt", "bo", "ba", "bw", "bv", "br", "io", "bn", "bg", "bf", "bi", "kh", "cm", "ca", "cv", "ky", "cf", "td", "cl", "cn", "cx", "cc", "co", "km", "cg", "cd", "ck", "cr", "ci", "hr", "cu", "cy", "cz", "dk", "dj", "dm", "do", "ec", "eg", "sv", "gq", "er", "ee", "et", "fk", "fo", "fj", "fi", "fr", "gf", "pf", "tf", "ga", "gm", "ge", "de", "gh", "gi", "gr", "gl", "gd", "gp", "gu", "gt", "gg", "gn", "gw", "gy", "ht", "hm", "va", "hn", "hk", "hu", "is", "in", "id", "ir", "iq", "ie", "im", "il", "it", "jm", "jp", "je", "jo", "kz", "ke", "ki", "kp", "kr", "kw", "kg", "la", "lv", "lb", "ls", "lr", "ly", "li", "lt", "lu", "mo", "mk", "mg", "mw", "my", "mv", "ml", "mt", "mh", "mq", "mr", "mu", "yt", "mx", "fm", "md", "mc", "mn", "me", "ms", "ma", "mz", "mm", "na", "nr", "np", "nl", "an", "nc", "nz", "ni", "ne", "ng", "nu", "nf", "mp", "no", "om", "pk", "pw", "ps", "pa", "pg", "py", "pe", "ph", "pn", "pl", "pt", "pr", "qa", "re", "ro", "ru", "rw", "sh", "kn", "lc", "pm", "vc", "ws", "sm", "st", "sa", "sn", "rs", "sc", "sl", "sg", "sk", "si", "sb", "so", "za", "gs", "es", "lk", "sd", "sr", "sj", "sz", "se", "ch", "sy", "tw", "tj", "tz", "th", "tl", "tg", "tk", "to", "tt", "tn", "tr", "tm", "tc", "tv", "ug", "ua", "ae", "gb", "um", "uy", "uz", "vu", "ve", "vn", "vg", "vi", "wf", "eh", "ye", "zm", "zw"}
	countries := make(map[string]string, len(regionCode))
	for i, v := range regionCode {
		countries[v] = strings.TrimSpace(regionName[i])
	}
	return countries
}()

func LtdCodeToCountryOrAreaName(Code string) string {
	code := strings.ToLower(Code)
	if country, ok := countryOrAreaNameByLtdCode[code]; ok {
		return country
	}
	return code
}

func DN42(ip string, _ time.Duration, _ string, _ bool) (*IPGeoData, error) {
	index, _ := dn42.LoadGeoFeedIndex()
	return lookupDN42(index, ip)
}

func newDN42SourceDescriptorSession(dotServer string, withGeoDNS bool) SourceDescriptorSession {
	return newDN42SourceDescriptorSessionWithLoader(dotServer, withGeoDNS, dn42.LoadGeoFeedIndex)
}

func newDN42SourceDescriptorSessionWithLoader(
	dotServer string,
	withGeoDNS bool,
	load func() (*dn42.GeoFeedIndex, error),
) SourceDescriptorSession {
	var current atomic.Pointer[SourceDescriptor]
	initialIndex, _ := load()
	initial := dn42SourceDescriptor(initialIndex, dotServer, withGeoDNS)
	current.Store(&initial)

	refresh := func() {
		index, _ := load()
		if index == nil {
			return
		}
		next := dn42SourceDescriptor(index, dotServer, withGeoDNS)
		for {
			previous := current.Load()
			if previous != nil && previous.HasGeneration && previous.Generation >= next.Generation {
				return
			}
			if current.CompareAndSwap(previous, &next) {
				return
			}
		}
	}

	return SourceDescriptorSession{
		Current: func() SourceDescriptor { return *current.Load() },
		Refresh: refresh,
	}
}

func dn42SourceDescriptor(index *dn42.GeoFeedIndex, dotServer string, withGeoDNS bool) SourceDescriptor {
	source := Source(func(ip string, _ time.Duration, _ string, _ bool) (*IPGeoData, error) {
		return lookupDN42(index, ip)
	})
	descriptor := SourceDescriptor{
		Source:    source,
		Namespace: SourceNamespaceDN42,
		Backend:   SourceBackendDN42GeoFeed,
	}
	if index != nil {
		descriptor.Generation = index.Generation()
		descriptor.HasGeneration = true
	}
	return applyGeoDNS(descriptor, dotServer, withGeoDNS)
}

func lookupDN42(index *dn42.GeoFeedIndex, ip string) (*IPGeoData, error) {
	data := &IPGeoData{}
	// 先解析传入过来的数据
	ipTmp := strings.Split(ip, ",")
	if len(ipTmp) > 1 {
		ip = ipTmp[0]
	}
	// 先查找 GeoFeed
	if addr, err := netip.ParseAddr(ip); err == nil && index != nil {
		if geo, find := index.Lookup(addr); find {
			data.Country = geo.LtdCode
			data.City = geo.City
			data.Asnumber = geo.ASN
			data.Owner = geo.IPWhois
		}
	}
	// 如果没找到，查找 PTR
	if len(ipTmp) > 1 {
		// 存在 PTR 记录
		if res, err := dn42.FindPtrRecord(ipTmp[1]); err == nil && res.LtdCode != "" {
			data.Country = res.LtdCode
			data.Prov = res.Region
			data.City = res.City
		}
	}

	data.Country = LtdCodeToCountryOrAreaName(data.Country)

	switch data.Country {
	case "Hong Kong":
		data.Country = "China"
		data.Prov = "Hong Kong"
	case "Taiwan":
		data.Country = "China"
		data.Prov = "Taiwan"
	case "Macao":
		data.Country = "China"
		data.Prov = "Macao"
	case "":
		data.Country = "Unknown"
	}

	return data, nil
}
