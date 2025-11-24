package enum

import (
	"context"
	// "gospyder/pkg/models"
	"gospyder/pkg/resolver"
	"strings"
)

func Recursive(ctx context.Context, pool *resolver.Pool, foundDomain string)(<-chan string, error) {
	out := make(chan string, 50)

	go func () {
		defer close(out)

		base := strings.Split(foundDomain, ".")[0]
		suffix := strings.Join(strings.Split(foundDomain, ".")[1:], ".")

		permutations := []string {
			base + "1",
			base +"2",
			"dev-" +base,
			"test-" +base,
			base + "-admin",
			"admin-" + base,
		}

		for _, perm := range permutations {
			select {
			case <-ctx.Done():
				return 
			default:
			}
			out <- perm + "." + suffix
		}
	}()
	return out, nil
}