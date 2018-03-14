package iridium

import (
	"crypto"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
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
