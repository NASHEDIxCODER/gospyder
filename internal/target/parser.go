package target

import (
	"net/url"
	"strings"
)

type Target struct{
	Original string
	Scheme string
	Host string
	Domain string
	URL string
}

func Normalize(input string) (*Target, error) {
	original := strings.TrimSpace(input)

	if !strings.HasPrefix(original, "http://") &&
		!strings.HasPrefix(original, "https://") {
		original = "http://" + original
	}
	u, err := url.Parse(original)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(u.Hostname())

	return &Target{
		Original: input,
		Scheme:   u.Scheme,
		Host:     host,
		Domain:   host,
		URL:      u.String(),
	}, nil
}