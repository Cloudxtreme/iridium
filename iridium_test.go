package iridium

import (
	"crypto"
	"crypto/rsa"
	"net"
	"testing"
	"time"

	dnssrv "github.com/miekg/dns"
)

var settings = &Settings{
	Addr:             "127.0.0.1:15353",
	AXFERPassword:    "random",
	MaxRecusion:      20,
	MaxNameservers:   4,
	QueryTimeout:     10 * time.Second,
	RootHintsURL:     "https://www.internic.net/domain/named.root",
	RootHintsRefresh: 24 * time.Hour,
	LimiterAge:       2 * time.Second,
	LimiterRecords:   10,
}

// Security
//DNSSecPublicKey  *dns.DNSKEY       // public key to sign dns records with
//DNSSecPrivateKey crypto.PrivateKey // private key to sign dns records with

func TestIridiumServer(t *testing.T) {

	// Generate signing key
	key, privKey, err := getKey()
	if err != nil {
		t.Errorf("failed to get key: %s", err)
	}
	settings.DNSSecPublicKey = key
	settings.DNSSecPrivateKey = privKey

	// Allow localhost anything
	_, ipnet, _ := net.ParseCIDR("127.0.0.1/32")
	settings.AllowedXfer.cidr = append(settings.AllowedXfer.cidr, *ipnet)

	// Start service

	s := New()
	s.LoadSettings(settings)
	s.Start()
	s.Stop()
}

func getKey() (*dnssrv.DNSKEY, crypto.PrivateKey, error) {
	key := new(dnssrv.DNSKEY)
	key.Hdr.Rrtype = dnssrv.TypeDNSKEY
	key.Hdr.Name = "example.com."
	key.Hdr.Class = dnssrv.ClassINET
	key.Hdr.Ttl = 14400
	key.Flags = 256
	key.Protocol = 3
	key.Algorithm = dnssrv.ECDSAP384SHA384
	// RSASHA256/2048
	// ECDSAP384SHA384/384
	privkey, err := key.Generate(384)
	if err != nil {
		return nil, nil, err
	}

	newPrivKey, err := key.NewPrivateKey(key.PrivateKeyString(privkey))
	if err != nil {
		return nil, nil, err
	}

	switch newPrivKey := newPrivKey.(type) {
	case *rsa.PrivateKey:
		newPrivKey.Precompute()
	}
	return key, newPrivKey, nil

}
