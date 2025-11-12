package scanner

import "context"

type Module interface{
	Name() string
	Scan(ctx context.Context, target string) ([]Result, error)
}
type Result struct{
	Vulnerability string `json:"vulnerability"`
	Target string `json:"target"`
	Description string `json:"description"`
	Severity string `json:"severity"` //low, medium, high
}