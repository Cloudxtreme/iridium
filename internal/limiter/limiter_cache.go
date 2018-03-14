package limiter

import (
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	MsgRateLimitReached = iota // 0
	MsgNotCached               // 1
	MsgCached                  // 2

)

type messageCache struct {
	Msg  dns.Msg
	Date time.Time
	Hits int
}

type Cache struct {
	sync.RWMutex
	MaxRecords int
	MaxAge     time.Duration
	Source     map[string][]messageCache
}

func New() *Cache {
	c := &Cache{
		Source:     make(map[string][]messageCache),
		MaxRecords: 10,
		MaxAge:     2 * time.Second,
	}
	go c.cleanMessageCacheTimer()
	return c
}

// GetCache checks if the request limit has been reached
func (c Cache) GetCache(client net.IP, msg *dns.Msg) int {
	c.Lock()
	defer c.Unlock()
	clientString := client.String()
	for id, cache := range c.Source[clientString] {
		if reflect.DeepEqual(cache.Msg.Question, msg.Question) {
			if cache.Hits > c.MaxRecords {
				return MsgRateLimitReached
			}
			// we have a previously answered question
			msg.Answer = cache.Msg.Answer
			msg.Ns = cache.Msg.Ns
			msg.Extra = cache.Msg.Extra

			msg.Authoritative = cache.Msg.Authoritative
			msg.RecursionAvailable = cache.Msg.RecursionAvailable
			c.Source[clientString][id].Hits++
			return MsgCached
		}
	}
	return MsgNotCached
}

// AddCache adds a message to the limiter cache
func (c Cache) AddCache(client net.IP, msg *dns.Msg) {
	c.Lock()
	defer c.Unlock()
	clientString := client.String()
	detail := messageCache{
		Msg:  *msg,
		Hits: 0,
		Date: time.Now().Add(c.MaxAge),
	}
	c.Source[clientString] = append(c.Source[clientString], detail)

}

// cleanMessageCacheTimer Clear up old record from limit cache every X duration
func (c Cache) cleanMessageCacheTimer() {
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			c.cleanMessageCache()
		}
	}
}

// cleanMessageCache Clear up old record from limit cache
func (c Cache) cleanMessageCache() {
	c.Lock()
	defer c.Unlock()
	tmp := make(map[string][]messageCache)

	for ip := range c.Source {
		tmp[ip] = c.Source[ip]
	}

	now := time.Now()
	for ip, cache := range tmp {
		for id := len(cache); id > 1; id-- {
			if tmp[ip][id].Date.Before(now) {
				c.Source[ip] = append(c.Source[ip][:id], c.Source[ip][id+1:]...)
			}
		}
	}
}
