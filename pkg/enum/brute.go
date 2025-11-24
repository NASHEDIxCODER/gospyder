package enum

import (
	"bufio"
	"context"
	"gospyder/pkg/models"
	"gospyder/pkg/resolver"
	"os"
	"strings"
	"sync"
)

// bruteforce performs parallel DNS brute-forcing

func BruteForce (ctx context.Context, pool *resolver.Pool, target string, wordlist string)(<-chan models.Domain, error){
	out:= make(chan models.Domain, 100)
	 file, err := os.Open(wordlist)
	if err != nil {
		return nil, err
	}
	go func() {
		defer close (out)
		defer file.Close()
		scanner := bufio.NewScanner(file)
		var wg sync.WaitGroup
		sem := make(chan struct{}, 500) //500 concurrent brute-force attemps 
		
		for scanner.Scan(){
			select{
			case <-ctx.Done():
				return 
			default:
			}
			subdomain := strings.TrimSpace(scanner.Text())
			if subdomain == ""{
				continue
			}
			fullDomain := subdomain+ "." + target
			wg.Add(1)
			go func (domain string){
				defer wg.Done()
				sem <-struct{}{}
				defer func () {<-sem }()
				ips, err := pool.Lookup(ctx, domain)
				if err == nil && len(ips) > 0{
					out <- models.Domain{
						Name: domain,
						Source: "brute",
						Found: ips,
					}
				}
			}(fullDomain)
		}
		wg.Wait()
	}()
	return out, nil
}