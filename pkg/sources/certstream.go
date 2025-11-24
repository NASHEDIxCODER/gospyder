package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gorilla/websocket"
	"gospyder/pkg/models"
)

// CertStreamClient connects to certificate transparency logs
type CertStreamClient struct {
	conn *websocket.Conn
}

// NewCertStream connects to the public CertStream API
func NewCertStream() (*CertStreamClient, error) {
	conn, _, err := websocket.DefaultDialer.Dial("wss://certstream.calidog.io", nil)
	if err != nil {
		return nil, fmt.Errorf("certstream dial: %w", err)
	}
	return &CertStreamClient{conn: conn}, nil
}

// Watch listens for certificates and extracts subdomains
func (c *CertStreamClient) Watch(ctx context.Context, targetDomain string, domains chan<- models.Domain) error {
	defer c.conn.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		var cert map[string]interface{}
		if err := json.Unmarshal(msg, &cert); err != nil {
			continue
		}

		// Extract leaf certificate data
		domainList := extractDomains(cert)
		for _, domain := range domainList {
			// Check if domain is a subdomain of our target
			if strings.HasSuffix(domain, "."+targetDomain) {
				select {
				case domains <- models.Domain{Name: domain, Source: "certstream"}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
	}
}

// extractDomains pulls all names from a certificate
func extractDomains(cert map[string]interface{}) []string {
	var domains []string
	
	// Navigate the nested JSON structure
	if leaf, ok := cert["leaf_cert"].(map[string]interface{}); ok {
		if names, ok := leaf["all_domains"].([]interface{}); ok {
			for _, n := range names {
				if name, ok := n.(string); ok {
					domains = append(domains, name)
				}
			}
		}
	}
	return domains
}