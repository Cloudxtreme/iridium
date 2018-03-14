package forwarder

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	dnssrv "github.com/miekg/dns"
)

/* for later */

// RootHintsURL contains the URL to get the root hints
var RootHintsURL = "https://www.internic.net/domain/named.root"

var forwardCache = Cache{
	Domain: make(map[string]QueryType),
}

func init() {
	parseRootHints(tmproot)
	go getRootHintsLoop()
}

func getRootHintsLoop() {
	hints, err := getRootHints()
	if err == nil {
		parseRootHints(hints)
	}
	t := time.NewTicker(24 * time.Hour)
	for {
		select {
		case <-t.C:
			hints, err := getRootHints()
			if err == nil {
				parseRootHints(hints)
			}
		}
	}
}

func getRootHints() (string, error) {

	req, err := http.NewRequest("GET", RootHintsURL, nil)
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Failed to get root hints at %s error:%s", RootHintsURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Status code did not return 200 (got:%d)", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Error reading HTTP Body: %s", err)
	}
	return string(body), err
}

func parseRootHints(body string) error {
	forwardCache.importZone(body)
	return nil
}

// RRtoRecord converts RR record to our own Record format
func RRtoRecord(r dnssrv.RR) Record {
	new := Record{}
	switch r.(type) {
	case *dnssrv.SOA, *dnssrv.NS, *dnssrv.TXT, *dnssrv.MX:
		// nu.nl.			10675	IN	TXT	"MS=ms73419602"
		fields := strings.Fields(r.String())
		if len(fields) >= 4 {
			ttl, _ := strconv.Atoi(fields[1])
			return Record{Name: "", Domain: fields[0], Type: fields[3], TTL: ttl, Target: strings.Join(fields[4:], "\t")}
		}
	default:
		fields := strings.Fields(r.String())
		if len(fields) >= 4 {
			host, domain := splitDomain(fields[0])
			ttl, _ := strconv.Atoi(fields[1])
			return Record{Name: host, Domain: domain, Type: fields[3], TTL: ttl, Target: strings.Join(fields[4:], "\t")}
		}
	}
	return new
}
