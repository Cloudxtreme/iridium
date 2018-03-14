package iridium

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"strings"
	"time"

	dnssrv "github.com/miekg/dns"
)

func (s *Server) dnsServe(msg *dnssrv.Msg, dnsHost string, dnsDomain string, dnsQuery uint16, client net.IP, bufsize uint16) {

	// find nameserver NS (self)
	// find nameserver A
	// check record

	// Get our original request first
	err := s.GetRecursive(msg, 0, dnsDomain, dnsQuery, dnsHost, client, false)
	if err != nil {
		// TODO: error handling
		//msg.Rcode = msg.
	}

	// Get the NS record to determain if we can send the authoritive flag and add the NS answers
	if dnsQuery != dnssrv.TypeNS {
		// Find NS records in our cache
		err := s.GetRecursive(msg, -1, dnsDomain, dnssrv.TypeNS, "", client, false) // -1 = NS
		if err == nil {
			msg.Authoritative = true
		}
	}
	o := new(dnssrv.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dnssrv.TypeOPT
	o.SetDo()
	o.SetUDPSize(bufsize)
	msg.Extra = append(msg.Extra, o)
}

// GetRecursive gets all records for a domain we serve
func (s *Server) GetRecursive(msg *dnssrv.Msg, level int, dnsDomain string, dnsQuery uint16, dnsHost string, client net.IP, honorTTL bool) error {

	records := []dnssrv.RR{}
	switch dnsQuery {
	case dnssrv.TypeA, dnssrv.TypeAAAA:
		// www.example.com.	0	IN	A	1.2.3.4
		rs, err := s.serverCache.Get(dnsDomain, "A", dnsHost, client, honorTTL)
		rs6, err := s.serverCache.Get(dnsDomain, "AAAA", dnsHost, client, honorTTL)
		rs = append(rs, rs6...)
		records, err = dnsRecordToRR(rs)
		if err != nil {
			return err
		}

		if err != nil {
			return err
		}

		appendRecords(msg, level, records)
		if len(records) > 0 {
			msg.RecursionAvailable = true
			s.serverCache.StatsAddRequestCount(rs[0].UUID())
			break
		}
		fallthrough // incase we did not find a typeA/AAAA, also check for typeCNAME
	case dnssrv.TypeCNAME:
		rs, err := s.serverCache.Get(dnsDomain, dnssrv.TypeToString[dnssrv.TypeCNAME], dnsHost, client, honorTTL)
		if err == ErrNotFound {
			return err
		}
		records, err = dnsRecordToRR(rs)
		if err != nil {
			return err
		}
		appendRecords(msg, level, records)
		// get A/AAAA records of CNAME
		for _, record := range records {
			h, d := splitDomain(strings.Fields(record.String())[4])
			c.GetRecursive(msg, level, d, dnssrv.TypeA, h, client, honorTTL)
		}
	case dnssrv.TypeNS:
		// example.com.	0	IN	NS	ns1.example.com.
		rs, err := c.Get(dnsDomain, dnssrv.TypeToString[dnsQuery], dnsHost, client, honorTTL)

		records, err = dnsRecordToRR(rs)
		if err != nil {
			return err
		}
		appendRecords(msg, level, records)
		for _, record := range records {
			h, d := splitDomain(strings.Fields(record.String())[4])
			c.GetRecursive(msg, 1, d, dnssrv.TypeA, h, client, honorTTL)
		}
	case dnssrv.TypeMX:
		// example.com.	0	IN	MX	10 ns1.example.com.
		rs, err := c.Get(dnsDomain, dnssrv.TypeToString[dnsQuery], dnsHost, client, honorTTL)
		records, err = dnsRecordToRR(rs)
		if err != nil {
			return err
		}
		appendRecords(msg, level, records)
		for _, record := range records {
			h, d := splitDomain(strings.Fields(record.String())[5])
			c.GetRecursive(msg, 1, d, dnssrv.TypeA, h, client, honorTTL)
		}
	case dnssrv.TypeAXFR:
		// handled in handler instead
	default:
		rs, err := c.Get(dnsDomain, dnssrv.TypeToString[dnsQuery], dnsHost, client, honorTTL)
		//fmt.Printf("Records gotten: %v\n", rs)
		records, err = dnsRecordToRR(rs)
		//fmt.Printf("Records gotten: %v %s\n", records, err)
		if err != nil {
			return err
		}
		appendRecords(msg, level, records)
	}

	return nil
}

func encapsulateSOA(records []dnssrv.RR) []dnssrv.RR {
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

func appendRecords(msg *dnssrv.Msg, level int, records []dnssrv.RR) {
	if DNSSecPublicKey != nil {
		records, _ = dnsRecordSign(records)
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

func containsRecord(records []dnssrv.RR, c uint16) bool {
	for _, rr := range records {
		if rr.Header().Class == c {
			return true
		}
	}
	return false
}

func dnsRecordToRR(records []Record) (result []dnssrv.RR, err error) {
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

func dnsRecordSign(records []dnssrv.RR) (result []dnssrv.RR, err error) {

	now := time.Now().UTC()
	incep := uint32(now.Add(-3 * time.Hour).Unix())     // 2+1 hours, be sure to catch daylight saving time and such
	expir := uint32(now.Add(7 * 24 * time.Hour).Unix()) // sign for a week

	domain := "example.com"

	soa := new(dnssrv.SOA) // TODO: get soa record and extract fields
	soa.Hdr = dnssrv.RR_Header{domain, dnssrv.TypeSOA, dnssrv.ClassINET, 14400, 0}
	soa.Ns = "ns1.example.com."
	soa.Mbox = "mail.example.com."
	soa.Serial = 1293945905
	soa.Refresh = 14400
	soa.Retry = 3600
	soa.Expire = 604800
	soa.Minttl = 86400

	var rrsigs []dnssrv.RR
	for _, r := range records {
		// Fill in the values of the Sig, before signing
		sig := new(dnssrv.RRSIG)
		sig.Hdr = dnssrv.RR_Header{domain, dnssrv.TypeSOA, dnssrv.ClassINET, soa.Refresh, 0}
		sig.TypeCovered = soa.Hdr.Rrtype
		sig.Labels = uint8(dnssrv.CountLabel(soa.Hdr.Name)) // works for all 3
		sig.OrigTtl = soa.Hdr.Ttl
		sig.Expiration = expir                // date -u '+%s' -d"2011-02-01 04:25:05"
		sig.Inception = incep                 // date -u '+%s' -d"2011-01-02 04:25:05"
		sig.KeyTag = DNSSecPublicKey.KeyTag() // Get the keyfrom the Key
		sig.SignerName = DNSSecPublicKey.Hdr.Name
		sig.Algorithm = dnssrv.RSASHA256

		if len(records) == 0 {
			return records, nil
		}
		err = sig.Sign(DNSSecPrivateKey.(*ecdsa.PrivateKey), []dnssrv.RR{r})
		if err != nil {
			// TODO: error handling
			//fmt.Printf("Signing Error:%s\n", err)
		}
		rrsigs = append(rrsigs, sig)
	}
	records = append(records, rrsigs...)
	return records, nil
}
