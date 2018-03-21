package iridium

import (
	"crypto/md5"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rdoorn/iridium/internal/forwarder"
	"github.com/rdoorn/iridium/internal/limiter"
	"github.com/rdoorn/iridium/internal/master"
)

type Server struct {
	sync.RWMutex
	addr          string
	axferPassword string
	serverTCP     *dns.Server
	serverUDP     *dns.Server
	stop          chan bool
	Log           chan string
	Channels      *ChannelManager
	Settings      *Settings
	/*masterCache   *cache.Cache
	forwardCache  *cache.Cache
	limiterCache  *limiter.Cache*/
	masterCache    Feed
	forwarderCache Feed
	limiterCache   Feed
}

// New creates a new DNS manager type
func New() *Server {
	m := &Server{
		//addr: addr,
		//allowedForwarding: []net.IPNet{},
		//allowedRequests:   []string{"A", "AAAA", "NS", "MX", "SOA", "TXT", "CAA", "ANY", "CNAME", "MB", "MG", "MR", "WKS", "PTR", "HINFO", "MINFO", "SPF"},
		Log:            make(chan string, 500),
		stop:           make(chan bool),
		serverTCP:      &dns.Server{},
		serverUDP:      &dns.Server{},
		masterCache:    master.New(),
		forwarderCache: forwarder.New(),
		limiterCache:   limiter.New(),
		Channels:       NewChannelManager(),
		Settings: &Settings{
			Addr:             "127.0.0.1:15353",
			AXFERPassword:    "random",
			MaxRecusion:      20,
			MaxNameservers:   4,
			QueryTimeout:     10 * time.Second,
			RootHintsURL:     "https://www.internic.net/domain/named.root",
			RootHintsRefresh: 24 * time.Hour,
			LimiterAge:       2 * time.Second,
			LimiterRecords:   10,
		},
	}
	return m
}

func (s *Server) LoadSettings(c *Settings) {
	s.Settings.Lock()
	defer s.Settings.Unlock()
	s.Settings = c
	/*
		s.limiterCache.Lock()
		defer s.limiterCache.Unlock()
		s.limiterCache.MaxAge = c.LimiterAge
		s.limiterCache.MaxRecords = c.LimiterRecords
	*/
}

// Start starts the DNS manager
func (s *Server) Start() error {
	if s.serverTCP != nil && s.Settings.Addr != s.serverTCP.Addr {
		s.Stop()
	}
	// start service
	s.log("Starting dns manager")
	dns.Handle(".", s)
	if err := s.startListener(); err != nil {
		return err
	}
	//go m.StartChannels()
	return nil
}

// Stop stops the DNS manager
func (s *Server) Stop() {
	// return if not started
	if s.serverTCP.Addr == "" {
		return
	}
	//m.Channels.quit <- true
	s.stopListener()
}

// AllowXfer tests if network is configured to allow AXFERS
func (s *Server) allowXfer(ipnet CIDRS) {
	s.Settings.Lock()
	defer s.Settings.Unlock()
	s.Settings.AllowedXfer = ipnet
}

// AllowForwarding tests if network is configured to allow Forwarding requests
func (s *Server) allowForwarding(ipnet CIDRS) {
	s.Settings.Lock()
	defer s.Settings.Unlock()
	s.Settings.AllowedForwarding = ipnet
}

// AllowRequests configures which dns requests to allow
func (s *Server) allowRequests(req []string) {
	s.Settings.Lock()
	defer s.Settings.Unlock()
	s.Settings.AllowedRequests = req
}

// Records returns json format of all dns records in dnscache
func (s *Server) Records() []byte {
	return s.masterCache.RecordsJSON()
}

func (s *Server) log(message string, args ...interface{}) {
	fmt.Printf("Logging: %s\n", fmt.Sprintf(message, args...))
	select {
	case s.Log <- fmt.Sprintf(message, args...):
	default:
	}
}

func md5sum(s string) string {
	h := md5.New()
	io.WriteString(h, s)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func ipAllowed(allowed CIDRS, client net.IP) bool {
	for _, cidr := range allowed.cidr {
		if cidr.Contains(client) {
			return true
		}
	}
	return false
}
