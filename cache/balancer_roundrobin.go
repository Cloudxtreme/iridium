package cache

import "sync/atomic"

// RoundRobin based loadbalancing interface for statistics
type RoundRobin struct{ Records }

// Less implements RoundRobin based loadbalancing by sorting based on RoundRobin counter
func (s RoundRobin) Less(i, j int) bool {
	return atomic.LoadInt64(&s.Records[i].Statistics.Requests) < atomic.LoadInt64(&s.Records[j].Statistics.Requests)
	//return s.Records[i].Statistics.Requests < s.Records[j].Statistics.Requests
}
