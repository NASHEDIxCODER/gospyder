package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NASHEDIxCODER/gospyder/pkg/enum"
	"github.com/NASHEDIxCODER/gospyder/pkg/resolver"
	"github.com/NASHEDIxCODER/gospyder/pkg/scanner"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

func PrintBanner() {
	banner := `
 ██████╗  ██████╗ ███████╗██████╗ ██╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝ ██╔═══██╗██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██║  ███╗██║   ██║███████╗██████╔╝ ╚████╔╝ ██║  ██║█████╗  ██████╔╝
██║   ██║██║   ██║╚════██║██╔═══╝   ╚██╔╝  ██║  ██║██╔══╝  ██╔══██╗
╚██████╔╝╚██████╔╝███████║██║        ██║   ██████╔╝███████╗██║  ██║
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝        ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

                by nashedi_x_coder
`
	fmt.Printf("%s%s%s\n", ColorCyan, banner, ColorReset)
}

func PrintSuccess(msg string) {
	fmt.Printf("%s✓ %s%s\n", ColorGreen, msg, ColorReset)
}

func PrintInfo(msg string) {
	fmt.Printf("%sℹ %s%s\n", ColorBlue, msg, ColorReset)
}

func PrintError(msg string) {
	fmt.Fprintf(os.Stderr, "%s✗ %s%s\n", ColorRed, msg, ColorReset)
}

func PrintWarning(msg string) {
	fmt.Printf("%s⚠ %s%s\n", ColorYellow, msg, ColorReset)
}

var ServiceMap = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
	443: "HTTPS", 465: "SMTPS", 587: "SMTP-TLS", 993: "IMAPS",
	995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
	3389: "RDP", 5000: "Flask", 5432: "PostgreSQL", 5900: "VNC",
	5984: "CouchDB", 6000: "X11", 6379: "Redis", 7001: "Cassandra",
	8000: "HTTP-Alt", 8008: "HTTP-Alt2", 8080: "HTTP-Proxy", 8161: "ActiveMQ",
	8443: "HTTPS-Alt", 8888: "Jupyter", 9000: "SonarQube", 9001: "HSQLDB",
	9042: "Cassandra-CQL", 9090: "Prometheus", 9100: "PDL", 9200: "Elasticsearch",
	11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-Alt", 50070: "HDFS-NN",
	4369: "Erlang", 2483: "Oracle-SSL",
}

// Expanded port list for comprehensive scanning
var DefaultPorts = "21,22,23,25,53,80,110,143,443,465,587,993,995,1433,1521,3306,3389,5000,5432,5900,5984,6000,6379,7001,8000,8008,8080,8161,8443,8888,9000,9042,9090,9200,11211,27017,50070"

func main() {
	enumPtr := flag.Bool("enum", false, "Enable subdomain enumeration")
	activePtr := flag.Bool("active", false, "Force active enumeration only")
	passivePtr := flag.Bool("passive", false, "Force passive enumeration only")
	domainPtr := flag.String("d", "", "Target domain (required)")
	enumWordlist := flag.String("w", "wordlists/subdomains.txt", "Wordlist for subdomain enum")

	portsPtr := flag.Bool("ports", false, "Enable port scanning")
	portsList := flag.String("ports-list", DefaultPorts, "Ports to scan")
	servicePtr := flag.Bool("service", false, "Enable service detection on ports")

	wafPtr := flag.Bool("waf", false, "Enable WAF detection")

	fuzzPtr := flag.Bool("fuzz", false, "Enable directory fuzzing")
	fuzzWordlist := flag.String("fuzz-wordlist", "wordlists/paths.txt", "Wordlist for fuzzing")
	fuzzURL := flag.String("fuzz-url", "", "Base URL to fuzz")

	outputPtr := flag.String("o", "", "Output file (.txt format)")
	threadsPtr := flag.Int("t", 500, "Number of concurrent threads")
	timeoutPtr := flag.Int("timeout", 10, "Timeout in minutes")
	verbosePtr := flag.Bool("v", false, "Verbose output")

	flag.Parse()

	PrintBanner()

	if *domainPtr == "" {
		PrintError("Target domain is required (-d flag)")
		fmt.Fprintf(os.Stderr, "\nUsage: gospyder -d example.com [options]\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	target := *domainPtr

	fmt.Printf("%sTarget:%s %s\n", ColorPurple, ColorReset, target)
	fmt.Printf("%sThreads:%s %d | %sTimeout:%s %dm\n\n",
		ColorPurple, ColorReset, *threadsPtr,
		ColorPurple, ColorReset, *timeoutPtr)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutPtr)*time.Minute)
	defer cancel()

	pool := resolver.NewPool([]string{
		"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
	})

	var wg sync.WaitGroup
	results := []string{}
	resultsMu := sync.Mutex{}

	if *enumPtr {
		wg.Add(1)
		go func() {
			defer wg.Done()
			active := *activePtr
			passive := *passivePtr
			if !active && !passive {
				active = true
			}

			domains := runEnumeration(ctx, target, pool, active, passive, *enumWordlist, *verbosePtr)
			resultsMu.Lock()
			results = append(results, domains...)
			resultsMu.Unlock()
		}()
	}

	if *portsPtr {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ports := runPortScan(ctx, target, *portsList, *servicePtr, *threadsPtr)
			resultsMu.Lock()
			results = append(results, ports...)
			resultsMu.Unlock()
		}()
	}

	if *wafPtr {
		wg.Add(1)
		go func() {
			defer wg.Done()
			waf := runWAFDetection(ctx, target)
			if waf != "" {
				resultsMu.Lock()
				results = append(results, waf)
				resultsMu.Unlock()
			}
		}()
	}

	if *fuzzPtr {
		if *fuzzURL == "" {
			PrintError("-fuzz-url is required for fuzzing")
			os.Exit(1)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			paths := runFuzzing(ctx, *fuzzURL, *fuzzWordlist, *threadsPtr)
			resultsMu.Lock()
			results = append(results, paths...)
			resultsMu.Unlock()
		}()
	}

	wg.Wait()
	printSummary(results, *outputPtr)
}

func runEnumeration(ctx context.Context, target string, pool *resolver.Pool, active, passive bool, wordlist string, verbose bool) []string {
	PrintInfo("Starting subdomain enumeration...")

	mode := "active"
	if active && passive {
		mode = "active+passive"
	} else if passive && !active {
		mode = "passive"
	}
	fmt.Printf("%sMode:%s %s\n", ColorCyan, ColorReset, mode)

	engine := enum.NewEngine(pool, 500)
	var modeFlag enum.EnumMode
	switch {
	case active && passive:
		modeFlag = enum.ModeBoth
	case passive && !active:
		modeFlag = enum.ModePassive
	default:
		modeFlag = enum.ModeActive
	}

	domains := engine.Run(ctx, target, wordlist, modeFlag)
	for _, d := range domains {
		fmt.Printf("%s%s%s\n", ColorGreen, d, ColorReset)
	}

	PrintSuccess(fmt.Sprintf("Enumeration: %d subdomains found", len(domains)))
	return domains
}

func runPortScan(ctx context.Context, target, portsList string, detectService bool, threads int) []string {
	PrintInfo("Starting port scan...")

	ports := parsePorts(portsList)
	fmt.Printf("%sPorts:%s %d to scan\n", ColorCyan, ColorReset, len(ports))

	portScanner := &scanner.PortScanner{}
	openPorts := portScanner.Scan(ctx, target, ports, threads)

	var results []string
	for _, port := range openPorts {
		service := ""
		if detectService {
			service = ServiceMap[port]
			if service == "" {
				service = "Unknown"
			}
			results = append(results, fmt.Sprintf("%s:%d [%s]", target, port, service))
			fmt.Printf("%s%s:%d%s %s[%s]%s\n",
				ColorGreen, target, port, ColorReset,
				ColorYellow, service, ColorReset)
		} else {
			results = append(results, fmt.Sprintf("%s:%d", target, port))
			fmt.Printf("%s%s:%d%s\n", ColorGreen, target, port, ColorReset)
		}
	}

	PrintSuccess(fmt.Sprintf("Port scan: %d open ports", len(openPorts)))
	return results
}

func parsePorts(portsStr string) []int {
	var ports []int
	for _, part := range strings.Split(portsStr, ",") {
		if strings.Contains(part, "-") {
			var start, end int
			fmt.Sscanf(part, "%d-%d", &start, &end)
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			if port, err := strconv.Atoi(part); err == nil {
				ports = append(ports, port)
			}
		}
	}
	return ports
}

func runWAFDetection(ctx context.Context, target string) string {
	PrintInfo("Starting WAF detection...")

	wafScanner := &scanner.WAFScanner{}
	waf := wafScanner.Detect(ctx, target)

	if waf != "" {
		result := fmt.Sprintf("WAF detected: %s", waf)
		PrintWarning(result)
		return result
	}

	PrintSuccess("No WAF detected")
	return ""
}

func runFuzzing(ctx context.Context, baseURL, wordlist string, threads int) []string {
	PrintInfo("Starting directory fuzzing...")

	if wordlist == "wordlists/paths.txt" {
		os.MkdirAll("wordlists", 0755)
		if _, err := os.Stat(wordlist); os.IsNotExist(err) {
			defaultPaths := []byte("admin\nconfig\nbackup\ntest\nlogin\napi\nv1\nv2\nprivate\nsecret\nwp-admin\ndashboard\nphpmyadmin")
			os.WriteFile(wordlist, defaultPaths, 0644)
		}
	}

	fuzzer := &scanner.Fuzzer{}
	found := fuzzer.Scan(ctx, baseURL, wordlist, threads)

	for _, path := range found {
		fmt.Printf("%s%s%s\n", ColorGreen, path, ColorReset)
	}

	PrintSuccess(fmt.Sprintf("Fuzzing: %d paths found", len(found)))
	return found
}

func printSummary(results []string, outputFile string) {
	fmt.Printf("\n%s╔═══════════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s║%s          SCAN SUMMARY                     %s║%s\n",
		ColorCyan, ColorReset, ColorCyan, ColorReset)
	fmt.Printf("%s╚═══════════════════════════════════════════╝%s\n", ColorCyan, ColorReset)
	fmt.Printf("%sTotal findings:%s %d\n\n", ColorPurple, ColorReset, len(results))

	if outputFile != "" {
		content := strings.Join(results, "\n")
		if err := os.WriteFile(outputFile, []byte(content+"\n"), 0644); err != nil {
			PrintError(fmt.Sprintf("Failed to save: %v", err))
		} else {
			PrintSuccess(fmt.Sprintf("Results saved to %s", outputFile))
		}
	}
}
