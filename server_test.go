package iridium

import (
	"net"
	"strings"
	"testing"
	"time"

	dnssrv "github.com/miekg/dns"
	"github.com/rdoorn/iridium/cache"
)

var address = "127.0.0.1:15355"

var _, net1, _ = net.ParseCIDR("127.0.0.1/32")
var _, net2, _ = net.ParseCIDR("127.0.0.2/32")

var recordsAdd = map[string][]cache.Record{
	"example.com.": []cache.Record{
		{Name: "", Type: "SOA", Target: "ns1.example.com. hostmaster.example.com. ###SERIAL### 3600 10 30 30", ClusterID: "localhost1", Online: true},
		{Name: "www", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true},
		{Name: "www", Type: "A", Target: "1.2.3.5", ClusterID: "localhost1", Online: true},
		{Name: "www", Type: "A", Target: "1.2.3.6", ClusterID: "localhost1", Online: false},
		{Name: "www3", Type: "CNAME", Target: "www.example.com", ClusterID: "localhost1", Online: true},
		{Name: "www2", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true},
		{Name: "", Type: "NS", Target: "ns1.example.com.", ClusterID: "localhost1", Online: true},
		{Name: "", Type: "NS", Target: "ns2.example.com.", ClusterID: "localhost1", Online: true},
		{Name: "", Type: "MX", Target: "10 mx1.example.com.", ClusterID: "localhost1", Online: true},
		{Name: "ns1", Type: "A", Target: "1.2.3.5", ClusterID: "localhost1", Online: true},
		{Name: "ns2", Type: "A", Target: "1.2.3.6", ClusterID: "localhost1", Online: true},
		{Name: "mx1", Type: "A", Target: "1.2.3.6", ClusterID: "localhost1", Online: true},
		{Name: "mx1", Type: "A", Target: "1.2.3.6", ClusterID: "localhost1", Online: true},
		{Name: "leastconnected", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true, Statistics: cache.Statistics{Connected: 2}, BalanceMode: "leastconnected"},
		{Name: "leastconnected", Type: "A", Target: "127.0.0.1", ClusterID: "localhost1", Online: true, Statistics: cache.Statistics{Connected: 1}, BalanceMode: "leastconnected"},
		{Name: "roundrobin", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true, Statistics: cache.Statistics{Requests: 2}, BalanceMode: "roundrobin"},
		{Name: "roundrobin", Type: "A", Target: "127.0.0.1", ClusterID: "localhost1", Online: true, Statistics: cache.Statistics{Requests: 1}, BalanceMode: "roundrobin"},
		{Name: "leasttraffic", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true, Statistics: cache.Statistics{TX: 2, RX: 2}, BalanceMode: "leasttraffic"},
		{Name: "leasttraffic", Type: "A", Target: "127.0.0.1", ClusterID: "localhost1", Online: true, Statistics: cache.Statistics{TX: 1, RX: 1}, BalanceMode: "leasttraffic"},
		{Name: "firstavailable", Type: "A", Target: "127.0.0.1", ClusterID: "localhost1", Online: true, BalanceMode: "firstavailable"},
		{Name: "firstavailable", Type: "A", Target: "1.2.3.5", ClusterID: "localhost1", Online: true, BalanceMode: "firstavailable"},
		{Name: "preference", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true, Preference: 2, BalanceMode: "preference"},
		{Name: "preference", Type: "A", Target: "127.0.0.1", ClusterID: "localhost1", Online: true, Preference: 1, BalanceMode: "preference"},
		{Name: "topology", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true, LocalNetworks: []net.IPNet{*net2}, BalanceMode: "topology"},
		{Name: "topology", Type: "A", Target: "127.0.0.1", ClusterID: "localhost1", Online: true, LocalNetworks: []net.IPNet{*net1}, BalanceMode: "topology"},
	},
}

var recordsRemove = map[string][]cache.Record{
	"example.com.": []cache.Record{
		{Name: "www2", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true},
	},
}

var serverSettings = &Settings{
	Addr:          "127.0.0.1:15353",
	AXFERPassword: "random",
}

func TestDNSServer(t *testing.T) {

	s := New()
	s.LoadSettings(serverSettings)

	_, ipnet, _ := net.ParseCIDR("127.0.0.1/32")
	cidrs := CIDRS{}
	cidrs.cidr = append(cidrs.cidr, *ipnet)
	s.allowForwarding(cidrs)
	s.allowXfer(cidrs)

	var err error
	// should do nothing
	/*
		key, privKey, err := getKey()
		if err != nil {
			t.Errorf("failed to get key: %s", err)
		}
		DNSSECKEY = key
		DNSSECPRIV = privKey
		fmt.Printf("KEy: %+v", key)
	*/

	//m.Stop()

	err = s.Start()
	if err != nil {
		t.Errorf("failed to start manager: %s", err)
	}
	err = s.Start()
	if err == nil {
		t.Errorf("successfully started manager again. should not be possible: %s", err)
	}

	/*
		address = "127.0.0.1:25353"
		m.addr = address
		err = m.Start()
		if err != nil {
			t.Errorf("failed to restart start manager on new address: %s", err)
		}
		if m.serverTCP.Addr != m.addr {
			t.Errorf("serverTCP Addr incorrect, expected:%s got:%s", m.serverTCP.Addr, m.addr)
		}
	*/

	// Add DNS Records to server
	for domain, records := range recordsAdd {
		for _, record := range records {
			s.masterCache.AddRecord(domain, record)
		}
	}

	// Remove DNS Records
	for domain, records := range recordsRemove {
		for _, record := range records {
			s.masterCache.RemoveRecord(domain, record)
		}
	}

	//m.Start()
	t.Run("queryCalls", func(t *testing.T) {
		t.Run("StaticQueries", s.testStaticQueries)
		t.Run("BalancedQueries", s.testBalancedQueries)
		t.Run("ForwardQueries", s.testForwardQueries)
		t.Run("AxferQueries", s.testAxferQueries)
	})

	//fmt.Printf("%s", m.Records())
	//time.Sleep(10 * time.Second)
	s.Stop()

	logs := channelReadStrings(s.Log, 1)
	if len(logs) == 0 {
		t.Errorf("expected log output for manager, but got nothing")
	}

	for _, log := range logs {
		t.Log("== LOG manager: ", log)
	}

}

func (s *Server) testStaticQueries(t *testing.T) {
	t.Parallel()

	c := new(dnssrv.Client)
	var m *dnssrv.Msg

	// MX
	m = new(dnssrv.Msg)
	m.SetEdns0(4096, true)
	m.SetQuestion("example.com.", dnssrv.TypeMX)
	r, _, err := c.Exchange(m, address)
	if err != nil {
		t.Errorf("Lookup failed for %+v: %s\n", m.Question, err)
	}
	return
	checkResult(t, r, 1, 2, 4) // request, answers, auth, extra

	// NS
	m = new(dnssrv.Msg)
	m.SetQuestion("example.com.", dnssrv.TypeNS)
	r, _, err = c.Exchange(m, address)
	if err != nil {
		t.Errorf("Lookup failed for %+v: %s\n", m.Question, err)
	}
	checkResult(t, r, 2, 0, 2) // request, answers, auth, extra

	// SOA
	m = new(dnssrv.Msg)
	m.SetQuestion("example.com.", dnssrv.TypeSOA)
	r, _, err = c.Exchange(m, address)
	if err != nil {
		t.Errorf("Lookup failed for %+v: %s\n", m.Question, err)
	}
	checkResult(t, r, 1, 2, 2) // request, answers, auth, extra

	// A
	m = new(dnssrv.Msg)
	m.SetQuestion("www.example.com.", dnssrv.TypeA)
	r, _, err = c.Exchange(m, address)
	if err != nil {
		t.Errorf("Lookup failed for %+v: %s\n", m.Question, err)
	}
	checkResult(t, r, 2, 2, 2) // request, answers, auth, extra

	// CNAME -> A + 0x20 encoding
	m = new(dnssrv.Msg)
	m.SetQuestion("Www3.ExAmpLe.CoM.", dnssrv.TypeA)
	r, _, err = c.Exchange(m, address)
	if err != nil {
		t.Errorf("Lookup failed for %+v: %s\n", m.Question, err)
	}
	checkResult(t, r, 3, 2, 2) // request, answers, auth, extra
	if strings.Index(r.Answer[0].String(), "Www3.ExAmpLe.CoM.") < 0 {
		t.Errorf("Request of Www3.ExAmpLe.CoM. did not return the exact case back (0x20 encoding)\n: %+v", r)
	}
}

func (s *Server) testBalancedQueries(t *testing.T) {
	t.Parallel()

	// Test all balance modes
	c := new(dnssrv.Client)
	for _, records := range recordsAdd {
		record := records[0]
		var m *dnssrv.Msg
		if record.BalanceMode != "" {
			m = new(dnssrv.Msg)
			m.SetQuestion(record.BalanceMode+".example.com.", dnssrv.TypeA)
			r, _, err := c.Exchange(m, address)
			if err != nil {
				t.Errorf("Lookup failed for %+v: %s\n", m.Question, err)
			}
			if strings.Index(r.Answer[0].String(), "127.0.0.1") < 0 {
				t.Errorf("Result of %s failed, expected 127.0.0.1 to be the record, got: %+v\n", record.BalanceMode, r.Answer[0])
			}
		}
	}
}

func (s *Server) testForwardQueries(t *testing.T) {
	t.Parallel()

	c := new(dnssrv.Client)
	var m *dnssrv.Msg
	var r *dnssrv.Msg
	var err error

	// google.com
	m = new(dnssrv.Msg)
	m.SetQuestion("wwW.gOOgle.com.", dnssrv.TypeA)
	r, _, err = c.Exchange(m, address)
	if err != nil {
		t.Errorf("Lookup failed for %+v: %s\n", m.Question, err)
	}
	checkResult(t, r, 1, 0, 0) // request, answers, auth, extra

	// nu.nl
	m = new(dnssrv.Msg)
	m.SetQuestion("wwW.nu.nl.", dnssrv.TypeA)
	r, _, err = c.Exchange(m, address)
	if err != nil {
		t.Errorf("Lookup failed for %+v: %s\n", m.Question, err)
	}
	checkResult(t, r, 9, 0, 0) // request, answers, auth, extra
}

func (s *Server) testAxferQueries(t *testing.T) {
	t.Parallel()
	password := md5sum(s.Settings.AXFERPassword)

	tr := new(dnssrv.Transfer)
	m := new(dnssrv.Msg)
	tr.TsigSecret = map[string]string{"axfr.": password}
	m.SetAxfr("example.com.")
	m.SetTsig("axfr.", dnssrv.HmacMD5, 300, time.Now().Unix())
	_, err := tr.In(m, address)
	if err != nil {
		t.Errorf("Axfer transfer failed: %s\n", err)
	}
}

// channelReadStrings reads a array of strings for the duration of timeout
func channelReadStrings(channel chan string, timeout time.Duration) (results []string) {
	for {
		select {
		case result := <-channel:
			results = append(results, result)
		case <-time.After(timeout * time.Second):
			return
		}
	}
}

func checkResult(t *testing.T, m *dnssrv.Msg, answers int, authoritive int, extra int) { // request, answers, auth, extra
	//fmt.Printf("got:%+v", m)
	if m == nil {
		t.Errorf("Request returned nil!")
		return
	}
	if len(m.Answer) != answers || len(m.Ns) != authoritive || len(m.Extra) != extra {
		t.Errorf("Request did not return the correct reply (answers:%d/%d authotitive:%d/%d extra:%d/%d)\n", answers, len(m.Answer), authoritive, len(m.Ns), extra, len(m.Extra))
		t.Errorf("Request in error: %+v\n", m)
	}
}
