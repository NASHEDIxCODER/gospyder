package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type PortScanner struct{}

func (ps *PortScanner) Scan(ctx context.Context, target string, ports []int, threads int) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Ensure threads doesn't exceed number of ports
	if threads > len(ports) {
		threads = len(ports)
	}

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

			// Use TCP connection with optimized timeout
			dialer := net.Dialer{
				Timeout: 3 * time.Second,
			}

			conn, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				return
			}
			defer conn.Close()

			mu.Lock()
			openPorts = append(openPorts, p)
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return openPorts
}

// ScanWithRetry performs port scanning with retry logic
func (ps *PortScanner) ScanWithRetry(ctx context.Context, target string, ports []int, threads, retries int, verbose bool) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Ensure threads doesn't exceed number of ports
	if threads > len(ports) {
		threads = len(ports)
	}

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

			// Try with retries
			var conn net.Conn
			var err error

			for attempt := 0; attempt <= retries; attempt++ {
				dialer := net.Dialer{
					Timeout: 3 * time.Second,
				}

				conn, err = dialer.DialContext(ctx, "tcp", address)
				if err == nil {
					defer conn.Close()
					mu.Lock()
					openPorts = append(openPorts, p)
					mu.Unlock()
					if verbose {
						log.Printf("[✓] Port %d open\n", p)
					}
					return
				}

				// Retry on failure
				if attempt < retries {
					select {
					case <-ctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
						// Backoff before retry
					}
					if verbose && attempt == 0 {
						log.Printf("[*] Retrying port %d (attempt %d/%d)\n", p, attempt+2, retries+1)
					}
				}
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}
