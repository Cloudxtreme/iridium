package cache

import (
	"fmt"
	"strconv"
	"strings"

	dnssrv "github.com/miekg/dns"
)

const (
	Found = iota
	ErrNotAuthorized
	ErrNotFound
	ErrMaxRecursion
	ErrBalanceFailure
	ErrNSNotFound
	ErrTimeout
)

// RRtoRecord converts RR record to our own Record format
func RRtoRecord(r dnssrv.RR) Record {
	new := Record{}
	switch r.(type) {
	case *dnssrv.SOA, *dnssrv.NS, *dnssrv.TXT, *dnssrv.MX:
		// nu.nl.			10675	IN	TXT	"MS=ms73419602"
		fields := strings.Fields(r.String())
		if len(fields) >= 4 {
			ttl, _ := strconv.Atoi(fields[1])
			return Record{Name: "", Domain: fields[0], Type: fields[3], TTL: ttl, Target: strings.Join(fields[4:], "\t")}
		}
	default:
		fields := strings.Fields(r.String())
		if len(fields) >= 4 {
			host, domain := SplitDomain(fields[0])
			ttl, _ := strconv.Atoi(fields[1])
			return Record{Name: host, Domain: domain, Type: fields[3], TTL: ttl, Target: strings.Join(fields[4:], "\t")}
		}
	}
	return new
}

func EncapsulateSOA(records []dnssrv.RR) []dnssrv.RR {
	var soa dnssrv.RR
	for i, record := range records {
		if record.Header().Rrtype == dnssrv.TypeSOA {
			records[0], records[i] = records[i], records[0]
			soa = records[0]
		}
	}
	records = append(records, soa)
	return records
}

func DnsRecordToRR(records []Record) (result []dnssrv.RR, err error) {
	for _, r := range records {
		var newRecord string
		if r.Name == "" {
			newRecord = fmt.Sprintf("%s %d %s %s", r.Domain, r.TTL, r.Type, r.Target)
		} else {
			newRecord = fmt.Sprintf("%s.%s %d %s %s", r.Name, r.Domain, r.TTL, r.Type, r.Target)
		}
		rr, err := dnssrv.NewRR(newRecord)
		if err != nil {
			return []dnssrv.RR{}, fmt.Errorf("Failed to convert record '%+v', error: %s", r, err)
		}
		result = append(result, rr)
	}

	return result, nil
}
