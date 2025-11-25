package resolver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type Resolver struct {
	server    string
	client    *net.Resolver
	rateLimit time.Duration
	lastReq   time.Time
	mu        sync.Mutex
}

type Pool struct {
	resolvers []*Resolver
	mu        sync.RWMutex
	current   int
}

func NewPool(servers []string) *Pool {
	pool := &Pool{}
	for _, server := range servers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", server+":53")
			},
		}
		pool.resolvers = append(pool.resolvers, &Resolver{
			server:    server,
			client:    r,
			rateLimit: 50 * time.Millisecond,
		})
	}
	return pool
}

func (p *Pool) Lookup(ctx context.Context, name string) ([]string, error) {
	for retries := 0; retries < 3; retries++ {
		resolver := p.nextResolver()
		
		resolver.mu.Lock()
		if time.Since(resolver.lastReq) < resolver.rateLimit {
			time.Sleep(resolver.rateLimit - time.Since(resolver.lastReq))
		}
		resolver.lastReq = time.Now()
		resolver.mu.Unlock()
		
		ips, err := resolver.client.LookupHost(ctx, name)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		
		time.Sleep(200 * time.Millisecond * time.Duration(retries+1))
	}
	
	return nil, fmt.Errorf("failed to resolve %s", name)
}

func (p *Pool) nextResolver() *Resolver {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	r := p.resolvers[p.current]
	p.current = (p.current + 1) % len(p.resolvers)
	return r
}