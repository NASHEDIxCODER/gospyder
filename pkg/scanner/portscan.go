package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type PortScanner struct{}

func (ps *PortScanner) Scan(ctx context.Context, target string, ports []int, threads int) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, threads)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			sem <- struct{}{}
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			openPorts = append(openPorts, p)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return openPorts
}