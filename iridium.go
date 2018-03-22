package iridium

import (
	"net"
	"sync"

	"github.com/rdoorn/iridium/forwarder"
	"github.com/rdoorn/iridium/limiter"
	"github.com/rdoorn/iridium/master"
)

//"github.com/rdoorn/iridium/server"

type Settings struct {
	sync.RWMutex
	// Server
	Addr              string   // Addr for service
	AXFERPassword     string   // password for XFERS of the DNS zone
	AllowedRequests   []string // dns query types to respond to
	AllowedXfer       CIDRS    // cidr allowed to do xfer
	AllowedForwarding CIDRS    // cidr allowed to forward

	Master    master.Settings    // contains master server settings
	Forwarder forwarder.Settings // contains forwarder server settings
	Limiter   limiter.Settings   // contains limiter server settings

	/*
		// Forward
		MaxRecusion       int           // how deep to recurse
		MaxNameservers    int           // number of dns servers to query simultainious
		QueryTimeout      time.Duration // query timeout for a dns server
		RootHintsURL      string        // url to get the roothints file
		RootHintsRefresh  time.Duration // interval to get roothints

		// Security
		DNSSecPublicKey  *dns.DNSKEY       // public key to sign dns records with
		DNSSecPrivateKey crypto.PrivateKey // private key to sign dns records with

		// Rate Limiting
		LimiterAge     time.Duration // how long to cache limiter records
		LimiterRecords int           // how many requests in cache before ignoring request
	*/
}

type CIDRS struct {
	cidr []net.IPNet
}
