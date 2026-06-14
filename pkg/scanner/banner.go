package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// BannerResult holds the result of banner grabbing for a port.
type BannerResult struct {
	Port    int
	Banner  string
	Service string
	Version string
}

// GrabBanner connects to a port and reads the initial banner.
// Timeout controls how long we wait for banner data.
func GrabBanner(ctx context.Context, target string, port int, timeout time.Duration) (string, error) {
	address := fmt.Sprintf("%s:%d", target, port)

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set read deadline to avoid hanging
	conn.SetDeadline(time.Now().Add(timeout))

	// Read initial banner (max 4KB)
	reader := bufio.NewReaderSize(conn, 4096)
	bannerBytes := make([]byte, 4096)
	n, err := reader.Read(bannerBytes)
	if err != nil {
		// Partial read is still useful (e.g. EOF is fine)
		if n == 0 {
			return "", err
		}
	}

	banner := strings.TrimSpace(string(bannerBytes[:n]))
	// Clean up non-printable characters
	banner = sanitizeBanner(banner)
	return banner, nil
}

// BannerGrabber performs banner grabbing across multiple ports using the worker pool pattern.
type BannerGrabber struct {
	Timeout time.Duration
}

// NewBannerGrabber creates a new banner grabber with the given timeout.
func NewBannerGrabber(timeout time.Duration) *BannerGrabber {
	return &BannerGrabber{Timeout: timeout}
}

// GrabAll performs banner grabbing for all ports, respecting the worker pool.
// Returns a map of port -> banner info.
func (bg *BannerGrabber) GrabAll(ctx context.Context, target string, ports []int, threads int) map[int]BannerResult {
	results := make(map[int]BannerResult)
	type portBanner struct {
		port   int
		banner string
	}

	bannerChan := make(chan portBanner, len(ports))
	sem := make(chan struct{}, threads)

	for _, port := range ports {
		go func(p int) {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			banner, err := GrabBanner(ctx, target, p, bg.Timeout)
			if err == nil && banner != "" {
				bannerChan <- portBanner{port: p, banner: banner}
			}
		}(port)
	}

	// Wait for all goroutines with a done channel
	done := make(chan struct{})
	go func() {
		for i := 0; i < len(ports); i++ {
			select {
			case pb := <-bannerChan:
				results[pb.port] = BannerResult{
					Port:   pb.port,
					Banner: pb.banner,
				}
			case <-ctx.Done():
				return
			}
		}
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	return results
}

// sanitizeBanner removes non-printable characters and trims whitespace.
func sanitizeBanner(banner string) string {
	var clean strings.Builder
	for _, r := range banner {
		if r >= 32 && r <= 126 || r == '\n' || r == '\r' || r == '\t' {
			clean.WriteRune(r)
		} else {
			clean.WriteRune('.')
		}
	}
	return strings.TrimSpace(clean.String())
}

// HTTPPorts are the ports that should receive HTTP probing.
var HTTPPorts = map[int]bool{
	80:   true,
	443:  true,
	8080: true,
	8443: true,
	8000: true,
	3000: true,
}

// ProbeHTTPPort performs an HTTP GET request to detect web server details.
// Returns the Server header value.
func ProbeHTTPPort(ctx context.Context, target string, port int, timeout time.Duration) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	address := fmt.Sprintf("%s://%s:%d/", scheme, target, port)

	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "GoSpyder/3.0")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	if server == "" {
		// If no server header, at least identify the scheme
		return strings.ToUpper(scheme)
	}
	return server
}