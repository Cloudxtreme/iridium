package forwarder

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rdoorn/iridium/internal/cache"
)

type Forwarder struct {
	sync.RWMutex

	MaxRecusion      int           // how deep to recurse
	MaxNameservers   int           // number of dns servers to query simultainious
	QueryTimeout     time.Duration // query timeout for a dns server
	RootHintsURL     string        // url to get the roothints file
	RootHintsRefresh time.Duration // interval to get roothints
	Cache            *cache.Cache
}

func New() *Forwarder {
	f := &Forwarder{
		Cache: cache.New(),
	}
	f.parseRootHints(tmproot)
	go f.getRootHintsLoop()
	return f
}
func (f *Forwarder) AddRecord(domainName string, record cache.Record) {
	f.Cache.AddRecord(domainName, record)
}

func (f *Forwarder) RemoveRecord(domainName string, record cache.Record) {
	f.Cache.RemoveRecord(domainName, record)
}

func (f *Forwarder) AddRecords(client net.IP, msg *dns.Msg) {

}

func (f *Forwarder) GetDomainRecords(domainName string, client net.IP, honorTTL bool) ([]cache.Record, int) {
	return []cache.Record{}, 0
}

func (f *Forwarder) DomainExists(domain string) bool {
	return f.Cache.DomainExists(domain)
}

func (f *Forwarder) GetRecords(client net.IP, msg *dns.Msg) int {
	return 0
}

func (f *Forwarder) ServeRequest(msg *dns.Msg, dnsHost string, dnsDomain string, dnsQuery uint16, client net.IP, bufsize uint16) {
	//func dnsForward(msg *dns.Msg, q dns.Question, client net.IP) {

	/*
		var dnsDomain string
		var dnsHost string
		switch q.Qtype {
		case dns.TypeSOA, dns.TypeNS, dns.TypeTXT, dns.TypeMX:
			dnsDomain = q.Name
		default:
			dnsHost, dnsDomain = splitDomain(q.Name)
		}*/

	// Check our existing cache
	err := f.getRecursive(msg, 0, dnsDomain, dnsQuery, dnsHost, client, true)
	if err == nil {
		return // we have the record from cache, so exit
	}

	// Get all records and add it to the cache, ignore its errors
	f.GetRecursiveForward(0, dnsDomain, dnsQuery, dnsHost)

	// Re-get from cache, it should be there now
	err = f.getRecursive(msg, 0, dnsDomain, dnsQuery, dnsHost, client, true)
	if err == nil {
		return // we have the record from cache, so exit
	}
	msg.Rcode = dns.RcodeNameError
	return
}

// GetRecursiveForward gets all records for a domain we do not serve
func (f *Forwarder) GetRecursiveForward(level int, dnsDomain string, dnsQuery uint16, dnsHost string) (rs []cache.Record, err int) {
	honorTTL := true
	client := net.IP{}

	if level > f.MaxRecusion {
		return []cache.Record{}, cache.ErrMaxRecursion
	}

	rs, result := f.Cache.Get(dnsDomain, dns.TypeToString[dnsQuery], dnsHost, client, honorTTL)
	if result == cache.Found {
		// find the NS servers to resolve this records
		var domain string
		if dnsHost == "" {
			_, domain = cache.SplitDomain(dnsDomain)
		} else {
			domain = dnsDomain
		}
		ns, result := f.GetRecursiveForward(level+1, domain, dns.TypeNS, "")
		if result != cache.Found {
			return nil, result
		}

		// extract A records from DNS reply:
		var nsA []string
		var nsAAAA []string
		for _, record := range ns {
			if record.Type == "A" { // TODO: ipv6 support for doing remote queries with an ipv6 addr
				nsA = append(nsA, record.Target)
			}
			if record.Type == "AAAA" {
				nsAAAA = append(nsAAAA, record.Target)
			}
		}
		// if we have ipv4 A records for dns servers, do a lookup
		if len(nsA) == 0 {
			return nil, cache.ErrNotFound
		}
		rs, result = f.Resolve(nsA, dnsHost, dnsDomain, dnsQuery)
		if result != cache.Found {
			return []cache.Record{}, cache.ErrNotFound
		}

	}

	switch dnsQuery {
	case dns.TypeA, dns.TypeAAAA:
		for _, record := range rs {
			if record.Type == "CNAME" {
				host, domain := cache.SplitDomain(record.Target)
				rsA, result := f.GetRecursiveForward(level+1, domain, dns.TypeA, host)
				if result != cache.Found {
					return rs, result
				}
				rs = append(rs, rsA...)
			}
		}
	case dns.TypeNS:
		for _, nss := range rs {
			if nss.Type != "NS" {
				continue
			}
			if matchingARecord(rs, "A", nss.Target) || matchingARecord(rs, "AAAA", nss.Target) {
				continue
			}
			host, domain := cache.SplitDomain(nss.Target)

			// final attempt to get missing NS records from cache
			rsA, result := f.GetRecursiveForward(level+1, domain, dns.TypeA, host)
			if result == cache.Found {
				for _, r := range rsA {
					if r.Name == host && r.Domain == domain {
						rs = append(rs, r)
					}
				}
			}
		}
	}
	return rs, cache.Found
}

func matchingARecord(rs []cache.Record, qtype string, target string) bool {
	for _, r := range rs {
		if r.FQDN() == target && r.Type == qtype {
			return true
		}
	}
	return false
}

func ipAllowed(allowed []net.IPNet, client net.IP) bool {
	for _, cidr := range allowed {
		if cidr.Contains(client) {
			return true
		}
	}
	return false
}

// GetRecursive gets all records for a domain we serve
func (f *Forwarder) getRecursive(msg *dns.Msg, level int, dnsDomain string, dnsQuery uint16, dnsHost string, client net.IP, honorTTL bool) error {

	//records := []dns.RR{}
	switch dnsQuery {
	case dns.TypeA, dns.TypeAAAA:
		// www.example.com.	0	IN	A	1.2.3.4
		rs, _ := f.Cache.Get(dnsDomain, "A", dnsHost, client, honorTTL)
		rs6, _ := f.Cache.Get(dnsDomain, "AAAA", dnsHost, client, honorTTL)
		rs = append(rs, rs6...)
		records, err := cache.DnsRecordToRR(rs)
		if err != nil {
			return err
		}

		f.appendRecords(msg, level, records)
		if len(records) > 0 {
			msg.RecursionAvailable = true
			f.Cache.StatsAddRequestCount(rs[0].UUID())
			break
		}
		fallthrough // incase we did not find a typeA/AAAA, also check for typeCNAME
	case dns.TypeCNAME:
		rs, errc := f.Cache.Get(dnsDomain, dns.TypeToString[dns.TypeCNAME], dnsHost, client, honorTTL)
		if errc == cache.ErrNotFound {
			return fmt.Errorf("not found in cache")
		}
		records, err := cache.DnsRecordToRR(rs)
		if err != nil {
			return err
		}
		f.appendRecords(msg, level, records)
		// get A/AAAA records of CNAME
		for _, record := range records {
			h, d := cache.SplitDomain(strings.Fields(record.String())[4])
			f.getRecursive(msg, level, d, dns.TypeA, h, client, honorTTL)
		}
	case dns.TypeNS:
		// example.com.	0	IN	NS	ns1.example.com.
		rs, _ := f.Cache.Get(dnsDomain, dns.TypeToString[dnsQuery], dnsHost, client, honorTTL)

		records, err := cache.DnsRecordToRR(rs)
		if err != nil {
			return err
		}
		f.appendRecords(msg, level, records)
		for _, record := range records {
			h, d := cache.SplitDomain(strings.Fields(record.String())[4])
			f.getRecursive(msg, 1, d, dns.TypeA, h, client, honorTTL)
		}
	case dns.TypeMX:
		// example.com.	0	IN	MX	10 ns1.example.com.
		rs, _ := f.Cache.Get(dnsDomain, dns.TypeToString[dnsQuery], dnsHost, client, honorTTL)
		records, err := cache.DnsRecordToRR(rs)
		if err != nil {
			return err
		}
		f.appendRecords(msg, level, records)
		for _, record := range records {
			h, d := cache.SplitDomain(strings.Fields(record.String())[5])
			f.getRecursive(msg, 1, d, dns.TypeA, h, client, honorTTL)
		}
	case dns.TypeAXFR:
		// handled in handler instead
	default:
		rs, _ := f.Cache.Get(dnsDomain, dns.TypeToString[dnsQuery], dnsHost, client, honorTTL)
		//fmt.Printf("Records gotten: %v\n", rs)
		records, err := cache.DnsRecordToRR(rs)
		//fmt.Printf("Records gotten: %v %s\n", records, err)
		if err != nil {
			return err
		}
		f.appendRecords(msg, level, records)
	}

	return nil
}

func (f *Forwarder) appendRecords(msg *dns.Msg, level int, records []dns.RR) {
	switch level {
	case -1:
		msg.Ns = append(msg.Ns, records...)
	case 0:
		msg.Answer = append(msg.Answer, records...)
	default:
		msg.Extra = append(msg.Extra, records...)
	}
}

func (f *Forwarder) RecordsJSON() []byte {
	f.Lock()
	defer f.Unlock()
	r, err := json.Marshal(f.Cache)
	if err != nil {
		return []byte("{}")
	}
	return r
}
