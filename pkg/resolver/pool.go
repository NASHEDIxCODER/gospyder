package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// resolver manages parallel DNS quries

type Resolver struct{
	servers [] string
	Client *net.Resolver
	rateLimit time.Duration
	mu	sync.Mutex
	lastReq time.Time
}
//pool holds multiple resolver for load balancing 
type Pool struct{
	resolvers []*Resolver
	mu	sync.Mutex
	current int // ROund-robin index
}

// New creates resolver for multiple DNS server

func NewPool (servers []string) *Pool{
	pool := &Pool{}
	for _, server := range servers{
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string ) (net.Conn, error){
				d:= net.Dialer{Timeout: 2*time.Second}
				return d.DialContext(ctx, "udp", server+":53")
			},
		}
		pool.resolvers = append(pool.resolvers, &Resolver{
			servers : [] string {server},
			Client : r,
			rateLimit: 50 * time.Millisecond, //20 req/sec per resolver 
		})
	}
	return pool
}
//lookup performs a rate-limited DNS lookup

func (p *Pool) Lookup(ctx context.Context, name string) ([]string,error){
	for retries := 0; retries <3; retries ++{
		resolver := p.nextResolver()
		//rate limit 
		resolver.mu.Lock()
		wait := resolver.rateLimit - time.Since(resolver.lastReq)
		if wait >0 {
			time.Sleep(wait)
		}
		resolver.lastReq =time.Now()
		resolver.mu.Unlock()

		//query
		ips, err := resolver.Client.LookupHost(ctx, name)
		if err == nil && len(ips) > 0{
			return ips, nil
		}
		time.Sleep(100 * time.Microsecond)//backoff before retry
	}
	return nil, fmt.Errorf("failed to resolve %s", name)
}


//nextResolver returns next resolver in round-robin fashion 

func (p *Pool) nextResolver() *Resolver{
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.resolvers[p.current]
	p.current = (p.current +1) % len(p.resolvers)
	return r
}