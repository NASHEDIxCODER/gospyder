package scanner

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// PortResult holds detailed information about an open port.
type PortResult struct {
	Port    int
	Banner  string
	Service string
	Version string
}

// ScanResult holds the results of an advanced port scan.
type ScanResult struct {
	OpenPorts []int
	Banners   map[int]string
}

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

// ScanWithBanners performs port scanning with banner grabbing in a single pass.
// This is more efficient than scanning first and grabbing banners in a second pass.
// Uses the same worker pool pattern as ScanWithRetry.
func (ps *PortScanner) ScanWithBanners(ctx context.Context, target string, ports []int, threads, retries int, timeout time.Duration, verbose bool) map[int]*PortResult {
	results := make(map[int]*PortResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	resultChan := make(chan *PortResult, len(ports))

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

			for attempt := 0; attempt <= retries; attempt++ {
				dialer := net.Dialer{Timeout: timeout}
				conn, err := dialer.DialContext(ctx, "tcp", address)
				if err != nil {
					if attempt < retries {
						select {
						case <-ctx.Done():
							return
						case <-time.After(100 * time.Millisecond):
						}
					}
					continue
				}

				// Connection successful - grab banner on the same connection
				conn.SetDeadline(time.Now().Add(timeout))
				reader := bufio.NewReaderSize(conn, 4096)
				bannerBytes := make([]byte, 4096)
				n, readErr := reader.Read(bannerBytes)

				banner := ""
				if readErr == nil || n > 0 {
					banner = sanitizeBanner(string(bannerBytes[:n]))
				}
				conn.Close()

				// Detect service and version from banner
				service, version := DetectService(p, banner)

				if verbose {
					svcInfo := service
					if version != "" {
						svcInfo += " " + version
					}
					if banner != "" {
						log.Printf("[✓] Port %d open - %s (banner: %s)\n", p, svcInfo, truncateBanner(banner, 60))
					} else {
						log.Printf("[✓] Port %d open - %s\n", p, svcInfo)
					}
				}

				resultChan <- &PortResult{
					Port:    p,
					Banner:  banner,
					Service: service,
					Version: version,
				}
				return
			}
		}(port)
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for pr := range resultChan {
		mu.Lock()
		results[pr.Port] = pr
		mu.Unlock()
	}

	return results
}

// truncateBanner truncates a banner string to the given max length for display.
func truncateBanner(banner string, maxLen int) string {
	if len(banner) <= maxLen {
		return banner
	}
	// Try to break at a space near the limit
	truncated := banner[:maxLen]
	if idx := strings.LastIndex(truncated, " "); idx > maxLen/2 {
		truncated = truncated[:idx]
	}
	return truncated + "..."
}