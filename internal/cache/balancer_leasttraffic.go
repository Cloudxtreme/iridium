package cache

import "sync/atomic"

// LeastTraffic based loadbalancing
type LeastTraffic struct{ Records }

// Less implements LeastTraffic based loadbalancing by sorting based on leasttraffic counter
func (s LeastTraffic) Less(i, j int) bool {
	// Fallback to round robin if we have no RX/TX values yet
	if atomic.LoadInt64(&s.Records[i].Statistics.RX)+atomic.LoadInt64(&s.Records[i].Statistics.TX) == 0 {
		//return s.Records[i].Statistics.Requests < s.Records[j].Statistics.Requests
		return atomic.LoadInt64(&s.Records[i].Statistics.Requests) < atomic.LoadInt64(&s.Records[j].Statistics.Requests)

	}
	return atomic.LoadInt64(&s.Records[i].Statistics.RX)+atomic.LoadInt64(&s.Records[i].Statistics.TX) < atomic.LoadInt64(&s.Records[j].Statistics.RX)+atomic.LoadInt64(&s.Records[j].Statistics.TX)
}
