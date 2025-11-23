package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type PortScanner struct{}

func (p *PortScanner) Name() string { return "portscan" }

func (p *PortScanner) Scan(ctx context.Context, ip string) ([]Result, error) {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	//common ports to scan
	ports := []int{22, 23, 21, 80, 443, 8080, 8443, 3000, 8000}

	semaphore := make(chan struct{}, 100)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, 1*time.Second)
			if err != nil {
				return //port closed
			}
			conn.Close()
			mu.Lock()
			results = append(results, Result{
				Vulnerability: "Open Port",
				Target:        address,
				Description:   fmt.Sprintf("Port %d is open", p),
				Severity:      "low",
			})
			mu.Unlock()
		}(port)

	}
	wg.Wait()
	return results, nil
}
