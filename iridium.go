package iridium

import (
	"crypto"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rdoorn/iridium/internal/cache"
)

//"github.com/rdoorn/iridium/internal/server"

type Settings struct {
	sync.RWMutex
	// Server
	Addr          string // Addr for service
	AXFERPassword string // password for XFERS of the DNS zone

	// Forward
	MaxRecusion       int           // how deep to recurse
	MaxNameservers    int           // number of dns servers to query simultainious
	QueryTimeout      time.Duration // query timeout for a dns server
	RootHintsURL      string        // url to get the roothints file
	RootHintsRefresh  time.Duration // interval to get roothints
	AllowedForwarding CIDRS         // cidr allowed to forward

	// Security
	AllowedRequests  []string          // dns query types to respond to
	AllowedXfer      CIDRS             // cidr allowed to do xfer
	DNSSecPublicKey  *dns.DNSKEY       // public key to sign dns records with
	DNSSecPrivateKey crypto.PrivateKey // private key to sign dns records with

	// Rate Limiting
	LimiterAge     time.Duration // how long to cache limiter records
	LimiterRecords int           // how many requests in cache before ignoring request
}

type CIDRS struct {
	cidr []net.IPNet
}

type Feed interface {
	//ServeRequest(ctx context.Context, msg *dns.Msg, q dns.Question, client net.IP)          // Main interface for requests?
	ServeRequest(msg *dns.Msg, dnsHost string, dnsDomain string, dnsQuery uint16, client net.IP, bufsize uint16) // main interface for a dns request
	AddRecord(domainName string, record cache.Record)                                                            // Add record to cache
	RemoveRecord(domainName string, record cache.Record)                                                         // Remove record from cache
	GetDomainRecords(domainName string, client net.IP, honorTTL bool) ([]cache.Record, int)                      // get multiple record for specific domain
	DomainExists(domain string) bool                                                                             // Check if domain exists in cache
	GetRecords(client net.IP, msg *dns.Msg) int                                                                  // Get multiple records from cache
	AddRecords(client net.IP, msg *dns.Msg)                                                                      // Add multiple records to cache
	RecordsJSON() []byte                                                                                         // returns json format of current cache
}
