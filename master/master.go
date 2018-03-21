package master

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rdoorn/iridium/internal/cache"
)

type Master struct {
	sync.RWMutex
	// Server
	//Addr          string // Addr for service
	//AXFERPassword string // password for XFERS of the DNS zone

	// Forward
	//MaxRecusion       int           // how deep to recurse
	//MaxNameservers    int           // number of dns servers to query simultainious
	//QueryTimeout      time.Duration // query timeout for a dns server
	//RootHintsURL      string        // url to get the roothints file
	//RootHintsRefresh  time.Duration // interval to get roothints
	//AllowedForwarding CIDRS         // cidr allowed to forward

	// Security
	AllowedRequests  []string          // dns query types to respond to
	AllowedXfer      []net.IPNet       // cidr allowed to do xfer
	DNSSecPublicKey  *dns.DNSKEY       // public key to sign dns records with
	DNSSecPrivateKey crypto.PrivateKey // private key to sign dns records with

	// Rate Limiting
	//LimiterAge     time.Duration // how long to cache limiter records
	//LimiterRecords int           // how many requests in cache before ignoring request

	Cache *cache.Cache
}

func New() *Master {
	m := &Master{
		Cache: cache.New(),
	}
	return m
}

func (m *Master) AddRecord(domainName string, record cache.Record) {
	m.Cache.AddRecord(domainName, record)
}

func (m *Master) RemoveRecord(domainName string, record cache.Record) {
	m.Cache.RemoveRecord(domainName, record)
}

func (m *Master) AddRecords(client net.IP, msg *dns.Msg) {

}

func (m *Master) GetDomainRecords(domainName string, client net.IP, honorTTL bool) ([]cache.Record, int) {
	return []cache.Record{}, 0
}

func (m *Master) DomainExists(domain string) bool {
	return m.Cache.DomainExists(domain)
}

func (m *Master) GetRecords(client net.IP, msg *dns.Msg) int {
	return 0
}

func (m *Master) ServeRequest(msg *dns.Msg, dnsHost string, dnsDomain string, dnsQuery uint16, client net.IP, bufsize uint16) {
	if m.Cache == nil {
		m.Cache = cache.New()
	}

	// find nameserver NS (self)
	// find nameserver A
	// check record

	// Get our original request first
	err := m.getRecursive(msg, 0, dnsDomain, dnsQuery, dnsHost, client, false)
	if err != nil {
		// TODO: error handling
		//msg.Rcode = msg.
	}

	// Get the NS record to determain if we can send the authoritive flag and add the NS answers
	if dnsQuery != dns.TypeNS {
		// Find NS records in our cache
		err := m.getRecursive(msg, -1, dnsDomain, dns.TypeNS, "", client, false) // -1 = NS
		if err == nil {
			msg.Authoritative = true
		}
	}
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetDo()
	o.SetUDPSize(bufsize)
	msg.Extra = append(msg.Extra, o)
}

// GetRecursive gets all records for a domain we serve
func (m *Master) getRecursive(msg *dns.Msg, level int, dnsDomain string, dnsQuery uint16, dnsHost string, client net.IP, honorTTL bool) error {

	//records := []dns.RR{}
	switch dnsQuery {
	case dns.TypeA, dns.TypeAAAA:
		// www.example.com.	0	IN	A	1.2.3.4
		rs, _ := m.Cache.Get(dnsDomain, "A", dnsHost, client, honorTTL)
		rs6, _ := m.Cache.Get(dnsDomain, "AAAA", dnsHost, client, honorTTL)
		rs = append(rs, rs6...)
		records, err := cache.DnsRecordToRR(rs)
		if err != nil {
			return err
		}

		m.appendRecords(msg, level, records)
		if len(records) > 0 {
			msg.RecursionAvailable = true
			m.Cache.StatsAddRequestCount(rs[0].UUID())
			break
		}
		fallthrough // incase we did not find a typeA/AAAA, also check for typeCNAME
	case dns.TypeCNAME:
		rs, errc := m.Cache.Get(dnsDomain, dns.TypeToString[dns.TypeCNAME], dnsHost, client, honorTTL)
		if errc == cache.ErrNotFound {
			return fmt.Errorf("not found in cache")
		}
		records, err := cache.DnsRecordToRR(rs)
		if err != nil {
			return err
		}
		m.appendRecords(msg, level, records)
		// get A/AAAA records of CNAME
		for _, record := range records {
			h, d := cache.SplitDomain(strings.Fields(record.String())[4])
			m.getRecursive(msg, level, d, dns.TypeA, h, client, honorTTL)
		}
	case dns.TypeNS:
		// example.com.	0	IN	NS	ns1.example.com.
		rs, _ := m.Cache.Get(dnsDomain, dns.TypeToString[dnsQuery], dnsHost, client, honorTTL)

		records, err := cache.DnsRecordToRR(rs)
		if err != nil {
			return err
		}
		m.appendRecords(msg, level, records)
		for _, record := range records {
			h, d := cache.SplitDomain(strings.Fields(record.String())[4])
			m.getRecursive(msg, 1, d, dns.TypeA, h, client, honorTTL)
		}
	case dns.TypeMX:
		// example.com.	0	IN	MX	10 ns1.example.com.
		rs, _ := m.Cache.Get(dnsDomain, dns.TypeToString[dnsQuery], dnsHost, client, honorTTL)
		records, err := cache.DnsRecordToRR(rs)
		if err != nil {
			return err
		}
		m.appendRecords(msg, level, records)
		for _, record := range records {
			h, d := cache.SplitDomain(strings.Fields(record.String())[5])
			m.getRecursive(msg, 1, d, dns.TypeA, h, client, honorTTL)
		}
	case dns.TypeAXFR:
		// handled in handler instead
	default:
		rs, _ := m.Cache.Get(dnsDomain, dns.TypeToString[dnsQuery], dnsHost, client, honorTTL)
		//fmt.Printf("Records gotten: %v\n", rs)
		records, err := cache.DnsRecordToRR(rs)
		//fmt.Printf("Records gotten: %v %s\n", records, err)
		if err != nil {
			return err
		}
		m.appendRecords(msg, level, records)
	}

	return nil
}

func encapsulateSOA(records []dns.RR) []dns.RR {
	var soa dns.RR
	for i, record := range records {
		if record.Header().Rrtype == dns.TypeSOA {
			records[0], records[i] = records[i], records[0]
			soa = records[0]
		}
	}
	records = append(records, soa)
	return records
}

func (m *Master) appendRecords(msg *dns.Msg, level int, records []dns.RR) {
	if m.DNSSecPublicKey != nil {
		records, _ = m.dnsRecordSign(records)
		msg.AuthenticatedData = true
	}

	switch level {
	case -1:
		msg.Ns = append(msg.Ns, records...)
	case 0:
		msg.Answer = append(msg.Answer, records...)
	default:
		msg.Extra = append(msg.Extra, records...)
	}
}

func containsRecord(records []dns.RR, c uint16) bool {
	for _, rr := range records {
		if rr.Header().Class == c {
			return true
		}
	}
	return false
}

func (m *Master) dnsRecordSign(records []dns.RR) (result []dns.RR, err error) {

	now := time.Now().UTC()
	incep := uint32(now.Add(-3 * time.Hour).Unix())     // 2+1 hours, be sure to catch daylight saving time and such
	expir := uint32(now.Add(7 * 24 * time.Hour).Unix()) // sign for a week

	domain := "example.com"

	soa := new(dns.SOA) // TODO: get soa record and extract fields
	soa.Hdr = dns.RR_Header{domain, dns.TypeSOA, dns.ClassINET, 14400, 0}
	soa.Ns = "ns1.example.com."
	soa.Mbox = "mail.example.com."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	var rrsigs []dns.RR
	for _, r := range records {
		// Fill in the values of the Sig, before signing
		sig := new(dns.RRSIG)
		sig.Hdr = dns.RR_Header{domain, dns.TypeSOA, dns.ClassINET, soa.Refresh, 0}
		sig.TypeCovered = soa.Hdr.Rrtype
		sig.Labels = uint8(dns.CountLabel(soa.Hdr.Name)) // works for all 3
		sig.OrigTtl = soa.Hdr.Ttl
		sig.Expiration = expir                  // date -u '+%s' -d"2011-02-01 04:25:05"
		sig.Inception = incep                   // date -u '+%s' -d"2011-01-02 04:25:05"
		sig.KeyTag = m.DNSSecPublicKey.KeyTag() // Get the keyfrom the Key
		sig.SignerName = m.DNSSecPublicKey.Hdr.Name
		sig.Algorithm = dns.RSASHA256

		if len(records) == 0 {
			return records, nil
		}
		err = sig.Sign(m.DNSSecPrivateKey.(*ecdsa.PrivateKey), []dns.RR{r})
		if err != nil {
			// TODO: error handling
			//fmt.Printf("Signing Error:%s\n", err)
		}
		rrsigs = append(rrsigs, sig)
	}
	records = append(records, rrsigs...)
	return records, nil
}

func (m *Master) RecordsJSON() []byte {
	m.Lock()
	defer m.Unlock()
	r, err := json.Marshal(m.Cache)
	if err != nil {
		return []byte("{}")
	}
	return r
}
