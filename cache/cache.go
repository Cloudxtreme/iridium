package cache

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	dnssrv "github.com/miekg/dns"
)

// Cache defines the main DNS cache
type Cache struct {
	sync.RWMutex
	Domain map[string]QueryType
}

// QueryType contains all records of queryType
type QueryType struct {
	QueryType map[string]HostRecord
}

// HostRecord contains all records of a Hostname
type HostRecord struct {
	HostRecord map[string]Records
}

// Records defines an array of record
type Records []Record

// Record of any type DNS
type Record struct {
	Name          string      `toml:"name" json:"name"`                   // hostname
	Domain        string      `toml:"domain" json:"domain"`               // domain
	Type          string      `toml:"type" json:"type"`                   // record type
	Target        string      `toml:"target" json:"target"`               // reply of record
	TTL           int         `toml:"ttl" json:"ttl"`                     // time to live
	ActivePassive string      `toml:"activepassive" json:"activepassive"` // used for monitoring only: record is active/passive setup
	ClusterNodes  int         `toml:"clusternodes" json:"clusternodes"`   // ammount of cluster nodes that should serve this domain (defaults to len(clusternodes))
	ClusterID     string      `toml:"clusterid" json:"clusterid"`         // cluster node this record belongs to
	BalanceMode   string      `toml:"balancemode" json:"balancemode"`     // balance mode of dns
	LocalNetworks []net.IPNet `toml:"localnetwork" json:"localnetwork"`   // used by balance mode: topology (if client matches local network, we prefer this record)
	Preference    int         `toml:"preference" json:"preference"`       // used by balance mode: preferred
	Statistics    Statistics  `toml:"statistics" json:"statistics"`       // statistics regarding this dns record
	uuidStr       string      // saved copy of generated uuid
	ttlExpire     time.Time   // time when the ttl has expired
	Online        bool        `toml:"online" json:"online"` // is record online (do we serve it)
	Local         bool        `toml:"local" json:"local"`   // true if record is of the local dns server
	//UUID          string      `toml:"uuid" json:"uuid"`     // links record to check that added it,usefull for removing dead checks
}

// UUID returns or genrates the UUID for record comparison
func (r *Record) UUID() string {
	// If we have a record, return it
	if r.uuidStr != "" {
		return r.uuidStr
	}
	// Generate a UUID, and return it
	var z []string
	for _, n := range r.LocalNetworks {
		z = append(z, fmt.Sprintf("%s:%s", n.IP, n.Mask))
	}
	sort.Strings(z)
	s := fmt.Sprintf("%s%s%s%s%d%s%d%s%s%d%t", r.Name, r.Domain, r.Type, r.Target, r.TTL, r.ActivePassive, r.ClusterNodes, r.ClusterID, r.BalanceMode, r.Preference, r.Local)
	h := sha256.New()
	h.Write([]byte(s))
	r.uuidStr = string(h.Sum(nil))
	return r.uuidStr
}

// FQDN returns the FQDN of a request
func (r *Record) FQDN() string {
	if r.Name == "" {
		return r.Domain
	}
	return fmt.Sprintf("%s.%s", r.Name, r.Domain)
}

var dnscache = Cache{
	Domain: make(map[string]QueryType),
}

// createTree creates the cache tree for futher record parsing
func (c *Cache) createTree(domainName string, queryType string) {
	searchDomain := strings.ToLower(domainName)

	c.Lock()
	defer c.Unlock()
	if _, ok := c.Domain[searchDomain]; !ok {
		c.Domain[searchDomain] = QueryType{
			QueryType: make(map[string]HostRecord),
		}
	}
	if _, ok := c.Domain[searchDomain].QueryType[queryType]; !ok {
		c.Domain[searchDomain].QueryType[queryType] = HostRecord{
			HostRecord: make(map[string]Records),
		}
	}
}

// Add adds a record to the dns cache
func (c *Cache) AddRecord(domainName string, record Record) {
	searchDomain := strings.ToLower(domainName)
	record.Name = strings.ToLower(record.Name)
	record.Domain = searchDomain
	if record.TTL == 0 {
		record.TTL = 10
	}
	record.ttlExpire = time.Now().Add(time.Duration(record.TTL) * time.Second)

	c.createTree(searchDomain, record.Type)
	c.Lock()
	defer c.Unlock()
	tmp := c.Domain[searchDomain].QueryType[record.Type].HostRecord[record.Name]
	tmp = append(tmp, record)
	c.Domain[searchDomain].QueryType[record.Type].HostRecord[record.Name] = tmp
}

func removeRecord(s []Record, i int) []Record {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

// Remove removed a record from the dns cache
func (c *Cache) RemoveRecord(domainName string, record Record) {
	searchDomain := strings.ToLower(domainName)
	recordToLower(&record)
	c.createTree(searchDomain, record.Type)
	c.Lock()
	defer c.Unlock()

	removeID := -1
	for id, oldrecord := range c.Domain[searchDomain].QueryType[record.Type].HostRecord[record.Name] {
		if record.UUID() == oldrecord.UUID() {
			removeID = id
		}
	}
	if removeID >= 0 {
		tmp := c.Domain[searchDomain].QueryType[record.Type].HostRecord[record.Name]
		tmp = removeRecord(tmp, removeID)
		if len(tmp) > 0 {
			c.Domain[searchDomain].QueryType[record.Type].HostRecord[record.Name] = tmp
		} else {
			delete(c.Domain[searchDomain].QueryType[record.Type].HostRecord, record.Name)
		}
	}
}

// Exists checks if a record exists in the dns cache
func (c *Cache) Exists(record Record) bool {
	c.Lock()
	defer c.Unlock()
	recordToLower(&record)
	if _, ok := c.Domain[record.Domain]; ok {
		if _, ok := c.Domain[record.Domain].QueryType[record.Type]; ok {
			if _, ok := c.Domain[record.Domain].QueryType[record.Type].HostRecord[record.Name]; ok {
				for _, r := range c.Domain[record.Domain].QueryType[record.Type].HostRecord[record.Name] {
					if r.UUID() == record.UUID() {
						return true
					}
				}
			}
		}
	}
	return false
}

// RecordTypeRemove removed a record from the dns cache
func (c *Cache) RecordTypeRemove(domainName string, record Record, queryType string) {
	searchDomain := strings.ToLower(domainName)
	recordToLower(&record)
	c.createTree(searchDomain, record.Type)
	c.Lock()
	defer c.Unlock()

	removeID := -1
	for id, oldrecord := range c.Domain[searchDomain].QueryType[record.Type].HostRecord[record.Name] {
		if oldrecord.Domain == record.Domain && oldrecord.Name == record.Name && oldrecord.Type == queryType {
			removeID = id
		}
	}
	if removeID >= 0 {
		tmp := c.Domain[searchDomain].QueryType[record.Type].HostRecord[record.Name]
		tmp = removeRecord(tmp, removeID)
		if len(tmp) > 0 {
			c.Domain[searchDomain].QueryType[record.Type].HostRecord[record.Name] = tmp
		} else {
			delete(c.Domain[searchDomain].QueryType[record.Type].HostRecord, record.Name)
		}
	}
}

// RecordTypeExists checks if a record exists in the dns cache
func (c *Cache) RecordTypeExists(record Record, queryType string) bool {
	c.Lock()
	defer c.Unlock()
	recordToLower(&record)
	if _, ok := c.Domain[record.Domain]; ok {
		if _, ok := c.Domain[record.Domain].QueryType[record.Type]; ok {
			if _, ok := c.Domain[record.Domain].QueryType[record.Type].HostRecord[record.Name]; ok {
				for _, r := range c.Domain[record.Domain].QueryType[record.Type].HostRecord[record.Name] {
					if r.Domain == record.Domain && r.Name == record.Name && r.Type == queryType {
						return true
					}
				}
			}
		}
	}
	return false
}

func recordToLower(record *Record) {
	record.Domain = strings.ToLower(record.Domain)
	record.Name = strings.ToLower(record.Name)
}

func (c *Cache) ImportZone(zone string) []Record {
	var records []Record
	for t := range dnssrv.ParseZone(strings.NewReader(zone), "", "") {
		if t.Error != nil {
			continue
		}
		record := RRtoRecord(t.RR)
		recordToLower(&record)

		// If record exists, re-add it to update TTL
		if c.Exists(record) {
			c.RemoveRecord(record.Domain, record)
		}

		// Only if we are the root domain, are we allowed to update the A records regardles of target
		// this to ensure there is only 1 A record per root server
		if record.Domain == "root-servers.net." && c.RecordTypeExists(record, "A") {
			c.RecordTypeRemove(record.Domain, record, "A")
		}
		if record.Domain == "root-servers.net." && c.RecordTypeExists(record, "AAAA") {
			c.RecordTypeRemove(record.Domain, record, "AAAA")
		}
		record.Online = true
		c.AddRecord(record.Domain, record)
		records = append(records, record)
	}
	return records
}

func New() *Cache {
	c := &Cache{
		Domain: make(map[string]QueryType),
	}
	return c
}

func SplitDomain(fqdn string) (string, string) {
	d := strings.Split(fqdn, ".")
	host := d[0]
	domain := strings.Join(d[1:], ".")
	if domain == "" {
		domain = "."
	}
	return host, domain
}
