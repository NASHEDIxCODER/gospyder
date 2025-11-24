package enum

import (
	"context"
	"gospyder/pkg/models"
	"gospyder/pkg/resolver"
	"gospyder/pkg/sources"
	"sync"
)

//Recursive takes found subdomains and genrates permutations

type Engine struct {
	pool *resolver.Pool
	seen map[string]bool
	seenMu sync.Mutex
	results []models.Domain
	resultsMu sync.Mutex
}

func NewEngine(pool *resolver.Pool) *Engine {
	return &Engine{
		pool: pool,
		seen: make(map[string]bool),
		results: []models.Domain{},
	}
}

func (e *Engine) Run(ctx context.Context, target string, wordlist string) []models.Domain{
	//duplication helper 
	markSeen := func (name string) bool {
		e.seenMu.Lock()
		if e.seen[name]{
			return true
		}
		e.seen[name] = true 
		return false 
	}
	addResult :=
}