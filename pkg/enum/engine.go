package enum

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/NASHEDIxCODER/gospyder/pkg/models"
	"github.com/NASHEDIxCODER/gospyder/pkg/resolver"
	"github.com/NASHEDIxCODER/gospyder/pkg/sources"
)

type EnumMode int

const (
	ModePassive EnumMode = iota
	ModeActive
	ModeBoth
)

type Engine struct {
	pool    *resolver.Pool
	threads int
	seen    sync.Map
}

func NewEngine(pool *resolver.Pool, threads int) *Engine {
	return &Engine{
		pool:    pool,
		threads: threads,
	}
}

func (e *Engine) Run(ctx context.Context, target string, wordlist string, mode EnumMode) []string {
	var results []string

	switch mode {
	case ModePassive:
		results = e.runPassive(ctx, target)
	case ModeActive:
		results = e.runActive(ctx, target, wordlist)
	case ModeBoth:
		results = append(e.runPassive(ctx, target), e.runActive(ctx, target, wordlist)...)
	}

	unique := []string{}
	seen := make(map[string]bool)
	for _, r := range results {
		if !seen[r] {
			seen[r] = true
			unique = append(unique, r)
		}
	}
	return unique
}

func (e *Engine) runPassive(ctx context.Context, target string) []string {
	log.Println("[*] Passive: Connecting to CertStream...")
	client, err := sources.NewCertStream()
	if err != nil {
		log.Printf("[!] CertStream unavailable: %v", err)
		return []string{}
	}

	domains := make(chan models.Domain, 100)
	go func() {
		client.Watch(ctx, target, domains)
		close(domains)
	}()

	var results []string
	for domain := range domains {
		if _, loaded := e.seen.LoadOrStore(domain.Name, true); !loaded {
			log.Printf("[PASSIVE] Found: %s", domain.Name)
			results = append(results, domain.Name)
		}
	}
	return results
}

func (e *Engine) runActive(ctx context.Context, target string, wordlist string) []string {
	log.Println("[*] Active: Starting brute-force...")
	stream, err := BruteForce(ctx, e.pool, target, wordlist)
	if err != nil {
		log.Printf("[!] Brute-force error: %v", err)
		return []string{}
	}

	var results []string
	var recursiveResults []string
	var recursiveMu sync.Mutex
	var recursiveWG sync.WaitGroup
	var collectorWG sync.WaitGroup
	recChan := make(chan string, 100)

	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for recDomain := range recChan {
			recursiveMu.Lock()
			recursiveResults = append(recursiveResults, recDomain)
			recursiveMu.Unlock()
		}
	}()

	for domain := range stream {
		if _, loaded := e.seen.LoadOrStore(domain.Name, true); !loaded {
			log.Printf("[ACTIVE] Found: %s", domain.Name)
			results = append(results, domain.Name)

			recursiveWG.Add(1)
			go func(d string) {
				defer recursiveWG.Done()
				e.runRecursive(ctx, d, recChan)
			}(domain.Name)
		}
	}

	recursiveWG.Wait()
	close(recChan)
	collectorWG.Wait()

	results = append(results, recursiveResults...)
	return results
}

func (e *Engine) runRecursive(ctx context.Context, foundDomain string, out chan<- string) {
	recCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	recStream, err := Recursive(recCtx, e.pool, foundDomain)
	if err != nil {
		log.Printf("[!] Recursive error: %v", err)
		return
	}

	for recDomain := range recStream {
		if _, loaded := e.seen.LoadOrStore(recDomain, true); !loaded {
			log.Printf("[RECURSIVE] Found: %s", recDomain)
			out <- recDomain
		}
	}
}
