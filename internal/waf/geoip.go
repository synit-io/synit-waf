package waf

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/oschwald/geoip2-golang/v2"
)

type countryLookup interface {
	LookupCountry(netip.Addr) (string, bool, error)
	Close() error
}

type maxMindCountryLookup struct {
	reader geoIPCountryReader
}

type geoIPCountryReader interface {
	Country(netip.Addr) (*geoip2.Country, error)
	Close() error
}

func openCountryLookup(path string) (countryLookup, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open GeoIP database: %w", err)
	}
	return newCountryLookup(reader)
}

func newCountryLookup(reader geoIPCountryReader) (countryLookup, error) {
	if err := validateCountryDatabase(reader); err != nil {
		return nil, errors.Join(err, reader.Close())
	}
	return &maxMindCountryLookup{reader: reader}, nil
}

func validateCountryDatabase(reader geoIPCountryReader) error {
	if _, err := reader.Country(netip.IPv4Unspecified()); err != nil {
		return fmt.Errorf("GeoIP database does not support country lookups: %w", err)
	}
	return nil
}

func (l *maxMindCountryLookup) LookupCountry(addr netip.Addr) (string, bool, error) {
	record, err := l.reader.Country(addr)
	if err != nil {
		return "", false, err
	}
	if !record.HasData() {
		return "", false, nil
	}
	code := strings.ToUpper(record.Country.ISOCode)
	if code == "" {
		code = strings.ToUpper(record.RegisteredCountry.ISOCode)
	}
	return code, code != "", nil
}

func (l *maxMindCountryLookup) Close() error {
	return l.reader.Close()
}
