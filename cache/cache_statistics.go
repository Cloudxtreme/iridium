package cache

import "sync/atomic"

// Statistics defines collectable statistics for a single DNS record
type Statistics struct {
	Requests  int64 `toml:"requests" json:"requests"`   // DNS Requests made to dns server
	Connected int64 `toml:"Connected" json:"Connected"` // Clients connected to service behind DNS
	TX        int64 `toml:"tx" json:"tx"`               // Traffic to service behind DNS
	RX        int64 `toml:"rx" json:"rx"`               // Traffic to service behind DNS
}

func (c *Cache) StatsAddRequestCount(uuid string) {
	c.Lock()
	defer c.Unlock()
	for id, d := range c.Domain {
		for iq, q := range d.QueryType {
			for ih, h := range q.HostRecord {
				for ir, r := range h {
					if r.UUID() == uuid {
						//c.Domain[id].QueryType[iq].HostRecord[ih][ir].Statistics.Requests++
						atomic.AddInt64(&c.Domain[id].QueryType[iq].HostRecord[ih][ir].Statistics.Requests, 1)

						//r.Statistics.Requests++
					}
				}
			}
		}
	}
}
