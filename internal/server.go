package iridium

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/rdoorn/iridium/internal/cache"
	"github.com/rdoorn/iridium/internal/limiter"
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
	serverCache   *cache.Cache
	forwardCache  *cache.Cache
	limiterCache  *limiter.Cache
}

// New creates a new DNS manager type
func New() *Server {
	m := &Server{
		//addr: addr,
		//allowedForwarding: []net.IPNet{},
		//allowedRequests:   []string{"A", "AAAA", "NS", "MX", "SOA", "TXT", "CAA", "ANY", "CNAME", "MB", "MG", "MR", "WKS", "PTR", "HINFO", "MINFO", "SPF"},
		Log:          make(chan string, 500),
		stop:         make(chan bool),
		serverTCP:    &dns.Server{},
		serverUDP:    &dns.Server{},
		serverCache:  cache.New(),
		forwardCache: cache.New(),
		limiterCache: limiter.New(),
		Channels:     NewChannelManager(),
	}
	return m
}

func (s *Server) LoadSettings(c *Settings) {
	s.Settings.Lock()
	defer s.Settings.Unlock()
	s.Settings = c
	s.limiterCache.Lock()
	defer s.limiterCache.Unlock()
	s.limiterCache.MaxAge = c.LimiterAge
	s.limiterCache.MaxRecords = c.LimiterRecords
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
func (s *Server) AllowXfer(ipnet []net.IPNet) {
	s.Settings.Lock()
	defer s.Settings.Unlock()
	s.allowedXfer = ipnet
}

// AllowForwarding tests if network is configured to allow Forwarding requests
func (s *Server) AllowForwarding(ipnet []net.IPNet) {
	s.Settings.Lock()
	defer s.Settings.Unlock()
	s.allowedForwarding = ipnet
}

// AllowRequests configures which dns requests to allow
func (s *Server) AllowRequests(req []string) {
	s.Settings.Lock()
	defer s.Settings.Unlock()
	s.allowedRequests = req
}

// Records returns json format of all dns records in dnscache
func (s *Server) Records() []byte {
	dnscache.Lock()
	defer dnscache.Unlock()
	r, err := json.Marshal(dnscache.Domain)
	if err != nil {
		return []byte("{}")
	}
	return r
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
	for _, cidr := range allowed {
		if cidr.Contains(client) {
			return true
		}
	}
	return false
}
