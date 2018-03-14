package iridium

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rdoorn/iridium/internal/cache"
	"github.com/rdoorn/iridium/internal/limiter"
)

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Compress = false

	var bufsize uint16
	var tcp bool
	if o := r.IsEdns0(); o != nil {
		bufsize = o.UDPSize()
	}
	if bufsize < 512 {
		bufsize = 512
	}
	// with TCP we can send 64K
	if tcp = isTCP(w); tcp {
		bufsize = dns.MaxMsgSize - 1
	}
	// go through the message requests
Opscode:
	switch r.Opcode {
	case dns.OpcodeQuery:
		clientIP := getClientIP(w.RemoteAddr().String())

		// Check if request is in cache
		switch s.limiterCache.GetCache(clientIP, msg) {
		case limiter.MsgRateLimitReached:
			return
		case limiter.MsgCached:
			break Opscode
		case limiter.MsgNotCached:
		}

		for _, q := range msg.Question {
			if !dns.IsFqdn(q.Name) || q.Name == "." {
				msg.SetRcode(r, dns.RcodeNotAuth)
				break Opscode
			}

			if s.serverCache.IsServedDomain(q.Name) {
				// Request is a domain name based request of a domain that we server: MX/DNS/XFER
				switch q.Qtype {
				case dns.TypeAXFR:
					if ipAllowed(s.Settings.AllowedXfer, clientIP) {
						ch := make(chan *dns.Envelope)
						tr := new(dns.Transfer)
						go tr.Out(w, r, ch)
						rs, _ := s.serverCache.GetAll(q.Name, clientIP, false)
						records, _ := cache.DnsRecordToRR(rs)
						records = cache.EncapsulateSOA(records)
						ch <- &dns.Envelope{RR: records}
						close(ch)
						w.Hijack()
						return
					}
					msg.Rcode = dns.RcodeRefused
				default:
					s.dnsServe(msg, "", q.Name, q.Qtype, clientIP, bufsize)
				}

				// Add to message cache
				s.limiterCache.AddCache(clientIP, msg)
			} else if s.serverCache.IsServedDomain(getDomain(q.Name)) {
				// we serve Any other record
				host, domain := splitDomain(q.Name)
				s.dnsServe(msg, host, domain, q.Qtype, clientIP, bufsize)
				msg.Authoritative = true

				// Add to message cache
				s.limiterCache.AddCache(clientIP, msg)

			} else if ipAllowed(s.Settings.AllowedForwarding, clientIP) {
				// we don't serve this record, but can forward
				s.dnsForward(msg, q, clientIP)
				continue
			} else {
				// denied
				msg.Rcode = dns.RcodeRefused
			}
		}
	}
	// TSIG
	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			// *Msg r has an TSIG record and it was validated
			msg.SetTsig("axfr.", dns.HmacMD5, 300, time.Now().Unix())
		} else {
			// *Msg r has an TSIG records and it was not valided
		}
	}
	// write back the result
	Fit(msg, int(bufsize), tcp)
	w.WriteMsg(msg)
}

func getDomain(fqdn string) string {
	d := strings.Split(fqdn, ".")
	return strings.Join(d[1:], ".")
}

func splitDomain(fqdn string) (string, string) {
	d := strings.Split(fqdn, ".")
	host := d[0]
	domain := strings.Join(d[1:], ".")
	if domain == "" {
		domain = "."
	}
	return host, domain
}

// TODO: proper ipv6
func getClientIP(addr string) net.IP {
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		addr = addr[:idx]
		// ugly for ipv6 parsing
		addr = strings.Replace(addr, "[", "", -1)
		addr = strings.Replace(addr, "]", "", -1)
	}
	return net.ParseIP(addr)
}

// isTCP returns true if the client is connecting over TCP.
func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

// Fit will make m fit the size. If a message is larger than size then entire
// additional section is dropped. If it is still to large and the transport
// is udp we return a truncated message.
// If the transport is tcp we are going to drop RR from the answer section
// until it fits. When this is case the returned bool is true.
func Fit(m *dns.Msg, size int, tcp bool) (*dns.Msg, bool) {
	if m.Len() > size {
		// Check for OPT Records at the end and keep those. TODO(miek)
		//m.Extra = nil
		m.Ns = nil
	}
	if m.Len() < size {
		return m, false
	}

	// With TCP setting TC does not mean anything.
	if !tcp {
		m.Truncated = true
		// fall through here, so we at least return a message that can
		// fit the udp buffer.
	}

	// Additional section is gone, binary search until we have length that fits.
	min, max := 0, len(m.Answer)
	original := make([]dns.RR, len(m.Answer))
	copy(original, m.Answer)
	for {
		if min == max {
			break
		}

		mid := (min + max) / 2
		m.Answer = original[:mid]

		if m.Len() < size {
			min++
			continue
		}
		max = mid

	}
	if max > 1 {
		max--
	}
	m.Answer = m.Answer[:max]
	return m, true
}
