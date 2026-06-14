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

		// Only use meaningful prefix/suffix mutations that could produce
		// valid subdomains. Avoid artificial numeric mutations (www1, www2)
		// that almost always return 404.
		perms := []string{
			"dev-" + base,
			"test-" + base,
			"staging-" + base,
			base + "-dev",
			base + "-test",
			"admin-" + base,
			base + "-admin",
			"api-" + base,
			base + "-api",
		}

		for _, perm := range perms {
			candidate := perm + "." + suffix

			// Only yield if DNS resolves AND the validation (done by caller) succeeds.
			// If DNS does not resolve, skip immediately - no need to push to channel.
			ips, err := pool.Lookup(ctx, candidate)
			if err != nil || len(ips) == 0 {
				continue
			}

			select {
			case <-ctx.Done():
				return
			case out <- candidate:
			}
		}
	}()

	return out, nil
}
