package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/NASHEDIxCODER/gospyder/pkg/models"
)

type CertStreamClient struct {
	conn *websocket.Conn
}

func NewCertStream() (*CertStreamClient, error) {
	conn, _, err := websocket.DefaultDialer.Dial("wss://certstream.calidog.io", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CertStream: %w", err)
	}
	return &CertStreamClient{conn: conn}, nil
}

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
			return fmt.Errorf("websocket read: %w", err)
		}

		var cert map[string]interface{}
		if err := json.Unmarshal(msg, &cert); err != nil {
			continue
		}

		for _, domain := range extractDomains(cert) {
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

func extractDomains(cert map[string]interface{}) []string {
	var domains []string
	
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