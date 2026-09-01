package transformers

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/dmachard/go-dnscollector/v3/dnsutils"
	"github.com/dmachard/go-dnscollector/v3/pkg/config"
	"github.com/dmachard/go-logger"
	"github.com/oschwald/maxminddb-golang"
)

type ASNRecord struct {
	AutonomousSystemNumber       int    `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

type CityRecord struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
}

type CountryRecord struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type CoordinateRecord struct {
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

type GeoRecord struct {
	Continent, CountryISOCode, City, ASN, ASO string
	Latitude, Longitude                       float64
}

type GeoIPTransform struct {
	GenericTransformer
	config                                 *config.TransformGeoIP
	dbCountry, dbCity, dbAsn, dbCoordinate *maxminddb.Reader
}

func NewDNSGeoIPTransform(cfg *config.TransformGeoIP, logger *logger.Logger, name string, instance int, nextWorkers []chan *dnsutils.DNSMessageBatch) *GeoIPTransform {
	t := &GeoIPTransform{config: cfg, GenericTransformer: NewTransformer(logger, "geoip", name, instance, nextWorkers)}
	return t
}

func (t *GeoIPTransform) GetTransforms() ([]Subtransform, error) {
	subtransforms := []Subtransform{}
	if t.config.Enable {
		if err := t.Open(); err != nil {
			return nil, fmt.Errorf("open error %w", err)
		}
		subtransforms = append(subtransforms, Subtransform{name: "geoip:lookup", processFunc: t.geoipTransform})
	}
	return subtransforms, nil
}

func (t *GeoIPTransform) Reset() {
	if t.config.Enable {
		t.Close()
	}
}

func (t *GeoIPTransform) Open() (err error) {
	// before to open, close all files
	// because open can be called also on reload
	t.Close()

	// open files ?
	if len(t.config.DBCountryFile) > 0 {
		t.dbCountry, err = maxminddb.Open(t.config.DBCountryFile)
		if err != nil {
			return err
		}
		t.LogInfo("country database loaded (%d records)", t.dbCountry.Metadata.NodeCount)
	}

	if len(t.config.DBCityFile) > 0 {
		t.dbCity, err = maxminddb.Open(t.config.DBCityFile)
		if err != nil {
			return err
		}
		t.LogInfo("city database loaded (%d records)", t.dbCity.Metadata.NodeCount)
	}

	if len(t.config.DBASNFile) > 0 {
		t.dbAsn, err = maxminddb.Open(t.config.DBASNFile)
		if err != nil {
			return err
		}
		t.LogInfo("asn database loaded (%d records)", t.dbAsn.Metadata.NodeCount)
	}

	if len(t.config.DBCoordinateFile) > 0 {
		t.dbCoordinate, err = maxminddb.Open(t.config.DBCoordinateFile)
		if err != nil {
			return err
		}
		t.LogInfo("coordinate database loaded (%d records)", t.dbCoordinate.Metadata.NodeCount)
	}
	return nil
}

func (t *GeoIPTransform) Close() {
	if t.dbCountry != nil {
		t.dbCountry.Close()
	}
	if t.dbCity != nil {
		t.dbCity.Close()
	}
	if t.dbAsn != nil {
		t.dbAsn.Close()
	}
	if t.dbCoordinate != nil {
		t.dbCoordinate.Close()
	}
}

func (t *GeoIPTransform) Lookup(ip string) (GeoRecord, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return GeoRecord{Continent: "-", CountryISOCode: "-", City: "-", ASN: "-", ASO: "-"}, fmt.Errorf("invalid IP: %s", ip)
	}
	return t.LookupParsed(parsedIP)
}

func (t *GeoIPTransform) LookupParsed(parsedIP net.IP) (GeoRecord, error) {
	if parsedIP == nil {
		return GeoRecord{Continent: "-", CountryISOCode: "-", City: "-", ASN: "-", ASO: "-"}, fmt.Errorf("nil IP")
	}

	rec := GeoRecord{Continent: "-", CountryISOCode: "-", City: "-", ASN: "-", ASO: "-"}

	if t.dbAsn != nil {
		var record ASNRecord
		err := t.dbAsn.Lookup(parsedIP, &record)
		if err != nil {
			return rec, err
		}
		rec.ASN = strconv.Itoa(record.AutonomousSystemNumber)
		rec.ASO = record.AutonomousSystemOrganization
	}

	if t.dbCity != nil {
		var record CityRecord
		err := t.dbCity.Lookup(parsedIP, &record)
		if err != nil {
			return rec, err
		}
		rec.City = record.City.Names.En
		rec.CountryISOCode = record.Country.ISOCode
		rec.Continent = record.Continent.Code

	} else if t.dbCountry != nil {
		var record CountryRecord
		err := t.dbCountry.Lookup(parsedIP, &record)
		if err != nil {
			return rec, err
		}
		rec.CountryISOCode = record.Country.ISOCode
		rec.Continent = record.Continent.Code
	}

	if t.dbCoordinate != nil {
		var record CoordinateRecord
		err := t.dbCoordinate.Lookup(parsedIP, &record)
		if err != nil {
			return rec, err
		}
		rec.Latitude = record.Location.Latitude
		rec.Longitude = record.Location.Longitude
	}

	return rec, nil
}

func (t *GeoIPTransform) geoipTransform(dm *dnsutils.DNSMessage) (int, error) {
	if dm.Geo == nil {
		dm.Geo = &dnsutils.TransformDNSGeo{CountryIsoCode: "-", City: "-", Continent: "-", AutonomousSystemNumber: "-", AutonomousSystemOrg: "-"}
	}

	var parsedIP net.IP

	// lookup ecs ip instead of the query ip?
	if t.config.LookupECS {
		// PowerDNS protobuf exposes ECS separately from parsed EDNS options.
		if dm.PowerDNS != nil && dm.PowerDNS.OriginalRequestSubnet != "" {
			parsedIP = net.ParseIP(dm.PowerDNS.OriginalRequestSubnet)
		}

		// DNStap, packet capture and other raw-DNS collectors.
		if parsedIP == nil && len(dm.EDNS.Options) > 0 {
			parsedIP = lookupECSIP(dm)
		}
	}

	// No usable ECS: fall back to the actual requester address.
	if parsedIP == nil {
		parsedIP = net.ParseIP(dm.NetworkInfo.GetQueryIP())
	}

	geoInfo, err := t.LookupParsed(parsedIP)
	if err != nil {
		return ReturnKeep, err
	}

	dm.Geo.Continent = geoInfo.Continent
	dm.Geo.CountryIsoCode = geoInfo.CountryISOCode
	dm.Geo.City = geoInfo.City
	dm.Geo.AutonomousSystemNumber = geoInfo.ASN
	dm.Geo.AutonomousSystemOrg = geoInfo.ASO
	dm.Geo.Latitude = geoInfo.Latitude
	dm.Geo.Longitude = geoInfo.Longitude

	return ReturnKeep, nil
}

// lookupECSIP extracts and parses the ECS IP from the EDNS options if available and valid.
func lookupECSIP(dm *dnsutils.DNSMessage) net.IP {
	for _, opt := range dm.EDNS.Options {
		if opt.Code == 8 {
			ecsIP := strings.Split(opt.Data, "/")[0]
			if ip := net.ParseIP(ecsIP); ip != nil {
				return ip
			}
		}
	}
	return nil
}
