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
	server [] string
	client *net.Resolver
	rateLimit time.Duration
	mu	sync.Mutex
	lastReq time.Time
}
//pool holds multiple resolver for load balancing 
type Pool struct{
	resolver []*Resolver
	mu	sync.Mutex
	current int // ROund-robin index
}

// New creates resolver for multiple DNS server