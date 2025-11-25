package enum

import (
	"context"
	"strings"

	"github.com/NASHEDIxCODER/gospyder/pkg/resolver"
)

func Recursive(ctx context.Context, pool *resolver.Pool, foundDomain string) (<-chan string, error) {
	out := make(chan string, 50)

	go func() {
		defer close(out)

		parts := strings.Split(foundDomain, ".")
		if len(parts) < 2 {
			return
		}

		base := parts[0]
		suffix := strings.Join(parts[1:], ".")

		perms := []string{
			base + "1",
			base + "2",
			"dev-" + base,
			"test-" + base,
			"staging-" + base,
			base + "-dev",
			base + "-test",
			"admin-" + base,
			base + "-admin",
		}

		for _, perm := range perms {
			select {
			case <-ctx.Done():
				return
			case out <- perm + "." + suffix:
			}
		}
	}()

	return out, nil
}