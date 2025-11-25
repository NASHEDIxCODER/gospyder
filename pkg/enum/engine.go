package enum

import (
	"context"
	"log"
	// "strings"
	"sync"
	"time"

	"gospyder/pkg/models"
	"gospyder/pkg/resolver"
	"gospyder/pkg/sources"
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
	var wg sync.WaitGroup
	recChan := make(chan string, 100)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for recDomain := range recChan {
			results = append(results, recDomain)
		}
	}()

	for domain := range stream {
		if _, loaded := e.seen.LoadOrStore(domain.Name, true); !loaded {
			log.Printf("[ACTIVE] Found: %s", domain.Name)
			results = append(results, domain.Name)

			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				e.runRecursive(ctx, d, recChan)
			}(domain.Name)
		}
	}

	time.Sleep(5 * time.Second)
	close(recChan)
	wg.Wait()

	return results
}

func (e *Engine) runRecursive(ctx context.Context, foundDomain string, out chan<- string) {
	recStream, err := Recursive(ctx, e.pool, foundDomain)
	if err != nil {
		log.Printf("[!] Recursive error: %v", err)
		return
	}

	for recDomain := range recStream {
		if _, exists := e.seen.Load(recDomain); exists {
			continue
		}

		ips, err := e.pool.Lookup(ctx, recDomain)
		if err == nil && len(ips) > 0 {
			if _, loaded := e.seen.LoadOrStore(recDomain, true); !loaded {
				log.Printf("[RECURSIVE] Found: %s", recDomain)
				out <- recDomain
			}
		}
	}
}