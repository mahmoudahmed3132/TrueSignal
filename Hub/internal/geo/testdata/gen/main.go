// Generates the test databases in ../ (DB-IP City Lite layout). Go ignores
// testdata, so this is not built with the Hub; run it from a scratch module:
//   go mod init gen && go get github.com/maxmind/mmdbwriter@v1.2.0 && go run . ..

package main

import (
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func city(cc, country, region, cityName string, lat, lon float64) mmdbtype.Map {
	names := func(s string) mmdbtype.Map { return mmdbtype.Map{"en": mmdbtype.String(s)} }
	m := mmdbtype.Map{
		"country":   mmdbtype.Map{"iso_code": mmdbtype.String(cc), "names": names(country)},
		"location":  mmdbtype.Map{"latitude": mmdbtype.Float64(lat), "longitude": mmdbtype.Float64(lon)},
		"continent": mmdbtype.Map{"code": mmdbtype.String("XX"), "names": names("x")},
	}
	if cityName != "" {
		m["city"] = mmdbtype.Map{"names": names(cityName)}
	}
	if region != "" {
		m["subdivisions"] = mmdbtype.Slice{mmdbtype.Map{"names": names(region)}}
	}
	return m
}

func write(path, dbType string, entries map[string]mmdbtype.Map) {
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 24, IncludeReservedNetworks: true, Description: map[string]string{"en": "TrueSignal test fixture"}})
	if err != nil {
		log.Fatal(err)
	}
	for cidr, rec := range entries {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, rec); err != nil {
			log.Fatal(err)
		}
	}
	f, _ := os.Create(path)
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		log.Fatal(err)
	}
}

func main() {
	entries := map[string]mmdbtype.Map{
		"81.2.69.0/24":    city("GB", "United Kingdom", "England", "London", 51.5142, -0.0931),
		"198.51.100.0/24": city("EG", "Egypt", "Cairo Governorate", "Cairo", 30.0444, 31.2357),
		"203.0.113.0/24":  city("US", "United States", "Virginia", "Ashburn", 39.0438, -77.4874),
		"2a02:c7f::/32":   city("DE", "Germany", "Berlin", "Berlin", 52.52, 13.405),
		"10.0.0.0/8":      city("ZZ", "Private", "", "", 0, 0), // must never be returned
	}
	write(os.Args[1]+"/dbip-city-test.mmdb", "DBIP-City-Lite", entries)
	write(os.Args[1]+"/dbip-country-test.mmdb", "DBIP-Country-Lite", map[string]mmdbtype.Map{"81.2.69.0/24": city("GB", "United Kingdom", "", "", 0, 0)})
}
