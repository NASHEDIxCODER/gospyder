package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"gospyder/pkg/scanner"
)



func main(){
	domain := flag.String("target", "", "Target domain to scan")

	flag.Parse()

	if *domain == ""{
		fmt.Println("Usage : gospyder -target example.com")
		os.Exit(1)
	}
	fmt.Printf("Starting scan of %s...\n", *domain)

	//create context with timeout
	ctx , cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
//initialize modules
	modules := []scanner.Module{ 
		&scanner.SubdomainScanner{},
		&scanner.PortScanner{},
	}
	//run all moduless
	allResults := []scanner.Result{}

	for _, module := range modules{
		fmt.Printf("\n[%s] Running...\n", module.Name())
		results, err := module.Scan(ctx, *domain)
		if err != nil{
			log.Printf("Module %s faild : %v", module.Name(),err)
		continue
		}
		allResults = append(allResults, results...)
		fmt.Printf("[%s] Found %d issues \n", module.Name(),len(results))

	}
	fmt.Printf("\n Scan Complete! Found %d total issues\n ",len(allResults))
	for _, r :=range allResults{
		fmt.Printf("[%s] %s - %s\n",r.Severity,r.Target,r.Description)
	}


}