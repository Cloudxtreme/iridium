package forwarder

import (
	"net"
	"time"

	dnssrv "github.com/miekg/dns"
)

type Settings struct {
	MaxRecusion      int           // how deep to recurse
	MaxNameservers   int           // number of dns servers to query simultainious
	QueryTimeout     time.Duration // query timeout for a dns server
	RootHintsURL     string        // url to get the roothints file
	RootHintsRefresh time.Duration // interval to get roothints

}

func dnsForward(msg *dnssrv.Msg, q dnssrv.Question, client net.IP) {

	var dnsDomain string
	var dnsHost string
	switch q.Qtype {
	case dnssrv.TypeSOA, dnssrv.TypeNS, dnssrv.TypeTXT, dnssrv.TypeMX:
		dnsDomain = q.Name
	default:
		dnsHost, dnsDomain = splitDomain(q.Name)
	}

	// Check our existing cache
	err := forwardCache.GetRecursive(msg, 0, dnsDomain, q.Qtype, dnsHost, client, true)
	if err == nil {
		return // we have the record from cache, so exit
	}

	// Get all records and add it to the cache, ignore its errors
	forwardCache.GetRecursiveForward(0, dnsDomain, q.Qtype, dnsHost)

	// Re-get from cache, it should be there now
	err = forwardCache.GetRecursive(msg, 0, dnsDomain, q.Qtype, dnsHost, client, true)
	if err == nil {
		return // we have the record from cache, so exit
	}
	msg.Rcode = dnssrv.RcodeNameError
	return
}

// GetRecursiveForward gets all records for a domain we do not serve
func (c *Cache) GetRecursiveForward(level int, dnsDomain string, dnsQuery uint16, dnsHost string) (rs []Record, err error) {
	honorTTL := true
	client := net.IP{}

	if level > maxRecusion {
		return []Record{}, ErrMaxRecursion
	}

	rs, err = c.Get(dnsDomain, dnssrv.TypeToString[dnsQuery], dnsHost, client, honorTTL)
	if err != nil {
		// find the NS servers to resolve this records
		var domain string
		if dnsHost == "" {
			_, domain = splitDomain(dnsDomain)
		} else {
			domain = dnsDomain
		}
		ns, err := c.GetRecursiveForward(level+1, domain, dnssrv.TypeNS, "")
		if err != nil {
			return nil, err
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
			return nil, ErrNotFound
		}
		rs, err = Resolve(nsA, dnsHost, dnsDomain, dnsQuery)
		if err != nil {
			return []Record{}, ErrNotFound
		}

	}

	switch dnsQuery {
	case dnssrv.TypeA, dnssrv.TypeAAAA:
		for _, record := range rs {
			if record.Type == "CNAME" {
				host, domain := splitDomain(record.Target)
				rsA, err := c.GetRecursiveForward(level+1, domain, dnssrv.TypeA, host)
				if err != nil {
					return rs, err
				}
				rs = append(rs, rsA...)
			}
		}
	case dnssrv.TypeNS:
		for _, nss := range rs {
			if nss.Type != "NS" {
				continue
			}
			if matchingARecord(rs, "A", nss.Target) || matchingARecord(rs, "AAAA", nss.Target) {
				continue
			}
			host, domain := splitDomain(nss.Target)

			// final attempt to get missing NS records from cache
			rsA, err := c.GetRecursiveForward(level+1, domain, dnssrv.TypeA, host)
			if err == nil {
				for _, r := range rsA {
					if r.Name == host && r.Domain == domain {
						rs = append(rs, r)
					}
				}
			}
		}
	}
	return rs, nil
}

func matchingARecord(rs []Record, qtype string, target string) bool {
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
