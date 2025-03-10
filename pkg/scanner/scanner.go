package scanner

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// HostResult represents the information of a detected host.
type HostResult struct {
	Address      string                 `json:"address"`       // IP address of the host.
	DnsName      string                 `json:"dns_name"`      // DNS name of the host, if available.
	Status       string                 `json:"status"`        // Status of the host (e.g., "active").
	CustomFields map[string]interface{} `json:"custom_fields"` // Custom fields associated with the host.
	OpenPorts    []int                  `json:"open_ports"`    // List of open ports on the host.
}

// SubnetScanResult stores the result of a scan on a subnet.
type SubnetScanResult struct {
	Subnet string       // Subnet in CIDR notation.
	Hosts  []HostResult // List of hosts discovered in the subnet.
}

// RunScan executes the scan process on the targetRange using concurrency.
// It divides the target range into smaller subnets (/24) if the range is larger than a /24.
// It returns a slice of HostResult, a map summarizing the number of hosts per subnet, and an error if any.
func RunScan(ctx context.Context, targetRange string, concurrencyLimit int, detailedIPLogs bool,
	dnsServer string, useSYNScan bool, enableOpenPorts bool,
	portsToScan string, managementPorts []int, enableManageable bool,
	manageableField string,
) ([]HostResult, map[string]int, error) {
	_, ipNet, err := net.ParseCIDR(targetRange)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid target range: %v", err)
	}
	ones, _ := ipNet.Mask.Size()
	var targets []string
	if ones < 24 {
		targets = SubdivideTo24(ipNet)
		log.Info().Msgf("Target range %s subdivided into %d /24 subnets.", targetRange, len(targets))
	} else {
		targets = []string{ipNet.String()}
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrencyLimit)
	resultChan := make(chan SubnetScanResult, len(targets))

	for i, t := range targets {
		select {
		case <-ctx.Done():
			log.Warn().Msg("Scan cancelled, aborting subnet discovery")
			return nil, nil, nil
		default:
		}
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			semaphore <- struct{}{}
			log.Info().Msgf("Starting discovery on subnet %s (%d/%d)", target, idx+1, len(targets))

			// Call the unified discovery function with appropriate parameters
			results := RunNetworkDiscovery(
				target,
				detailedIPLogs,
				dnsServer,
				useSYNScan,
				enableOpenPorts,
				portsToScan,
				managementPorts,
				enableManageable,
				manageableField,
			)

			log.Info().Msgf("Discovery complete on subnet %s: %d hosts detected", target, len(results))
			resultChan <- SubnetScanResult{Subnet: target, Hosts: results}
			<-semaphore
		}(i, t)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var overallResults []HostResult
	subnetSummary := make(map[string]int)
	for res := range resultChan {
		subnetSummary[res.Subnet] = len(res.Hosts)
		overallResults = append(overallResults, res.Hosts...)
	}
	return overallResults, subnetSummary, nil
}

// RunNetworkDiscovery is the main unified discovery function that orchestrates
// the scanning process based on configuration
func RunNetworkDiscovery(target string, detailedIPLogs bool, dnsServer string,
	useSYNScan bool, enableOpenPorts bool,
	portsToScan string, managementPorts []int,
	enableManageable bool, manageableField string,
) []HostResult {
	discovered := make(map[string]nmap.Host)
	allIPs := GenerateIPs(target)

	// Determine scan order based on whether port scanning is enabled
	if enableOpenPorts {
		// When port scanning is enabled, run port scan first, then ping scan on remaining IPs
		log.Info().Msg("Open ports scanning enabled - running port scan first, then ping scan on remaining IPs")

		// Perform port scan
		portScanResults := runPortScan(allIPs, detailedIPLogs, useSYNScan, portsToScan)

		// Add port scan results to discovered hosts
		for ip, host := range portScanResults {
			discovered[ip] = host
		}

		// Get IPs that weren't found in the port scan
		var remainingIPs []string
		for _, ip := range allIPs {
			if _, exists := discovered[ip]; !exists {
				remainingIPs = append(remainingIPs, ip)
			}
		}

		// Run ping scan on remaining IPs
		if len(remainingIPs) > 0 {
			log.Info().Msgf("Running ping scan on %d remaining IPs", len(remainingIPs))
			pingScanResults := runPingScanOnIPs(remainingIPs, detailedIPLogs)

			// Add ping scan results to discovered hosts
			for ip, host := range pingScanResults {
				discovered[ip] = host
			}
		}
	} else {
		// When port scanning is disabled, run ping scan first
		log.Info().Msg("Default scan order - running ping scan first")

		// Perform ping scan
		pingScanResults := runPingScan(target, detailedIPLogs)

		// Add ping scan results to discovered hosts
		for ip, host := range pingScanResults {
			discovered[ip] = host
		}

		// If open ports scanning is enabled (which should be false here, but checking for completeness),
		// scan the discovered hosts for open ports
		if enableOpenPorts && len(discovered) > 0 {
			// Get list of discovered IPs
			var discoveredIPs []string
			for ip := range discovered {
				discoveredIPs = append(discoveredIPs, ip)
			}

			log.Info().Msgf("Running port scan on %d discovered hosts", len(discoveredIPs))
			portScanResults := runPortScan(discoveredIPs, detailedIPLogs, useSYNScan, portsToScan)

			// Update host information with port scan results
			for ip, host := range portScanResults {
				discovered[ip] = host
			}
		}
	}

	// Convert discovered hosts to results
	results := convertDiscoveredToResults(discovered, dnsServer)

	// Check for manageable hosts if enabled
	if enableManageable {
		for i := range results {
			isManageable := isHostManageable(results[i].OpenPorts, managementPorts)
			results[i].CustomFields[manageableField] = isManageable

			if isManageable && detailedIPLogs {
				log.Info().Msgf("Host %s is remotely manageable", results[i].Address)
			}
		}
	}

	return results
}

// runPingScan performs a quick ping scan on the given target
func runPingScan(target string, detailedIPLogs bool) map[string]nmap.Host {
	discovered := make(map[string]nmap.Host)

	log.Info().Msgf("Starting ping scan on target: %s", target)

	pingScanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPingScan(),
		nmap.WithSYNDiscovery(),
		nmap.WithACKDiscovery(),
		nmap.WithICMPEchoDiscovery(),
		nmap.WithICMPTimestampDiscovery(),
		nmap.WithHostTimeout(5*time.Second),
	)
	if err != nil {
		log.Error().Msgf("Error creating ping scanner: %v", err)
		return discovered
	}

	pingResult, warnings, err := pingScanner.Run()
	if warnings != nil {
		log.Debug().Msgf("Ping scan warnings: %v", warnings)
	}

	if err != nil {
		log.Error().Msgf("Ping scan error on %v: %v", target, err)
	} else if pingResult != nil {
		for _, host := range pingResult.Hosts {
			if strings.ToLower(host.Status.State) == "up" {
				ip := ExtractIP(host)
				if ip != "" {
					discovered[ip] = host
					if detailedIPLogs {
						log.Info().Msgf("Host %s discovered during ping scan", ip)
					}
				}
			}
		}
	}

	log.Info().Msgf("Ping scan complete. Discovered %d hosts.", len(discovered))
	return discovered
}

// runPingScanOnIPs performs a ping scan on specific IPs
func runPingScanOnIPs(ips []string, detailedIPLogs bool) map[string]nmap.Host {
	discovered := make(map[string]nmap.Host)

	if len(ips) == 0 {
		return discovered
	}

	log.Info().Msgf("Starting ping scan on %d IPs", len(ips))

	pingScanner, err := nmap.NewScanner(
		nmap.WithTargets(ips...),
		nmap.WithPingScan(),
		nmap.WithSYNDiscovery(),
		nmap.WithACKDiscovery(),
		nmap.WithICMPEchoDiscovery(),
		nmap.WithICMPTimestampDiscovery(),
		nmap.WithHostTimeout(5*time.Second),
	)
	if err != nil {
		log.Error().Msgf("Error creating ping scanner for IPs: %v", err)
		return discovered
	}

	pingResult, warnings, err := pingScanner.Run()
	if warnings != nil {
		log.Debug().Msgf("Ping scan warnings: %v", warnings)
	}

	if err != nil {
		log.Error().Msgf("Ping scan error: %v", err)
	} else if pingResult != nil {
		for _, host := range pingResult.Hosts {
			if strings.ToLower(host.Status.State) == "up" {
				ip := ExtractIP(host)
				if ip != "" {
					discovered[ip] = host
					if detailedIPLogs {
						log.Info().Msgf("Host %s discovered during ping scan", ip)
					}
				}
			}
		}
	}

	log.Info().Msgf("Ping scan complete. Discovered %d hosts.", len(discovered))
	return discovered
}

// Modificaciones para mejorar los logs de tiempo en el escaneo
// Estas funciones se agregan al archivo scanner.go

// runPortScan con mejoras de timing logs
func runPortScan(ips []string, detailedIPLogs bool, useSYNScan bool, portsToScan string) map[string]nmap.Host {
	discovered := make(map[string]nmap.Host)

	if len(ips) == 0 {
		return discovered
	}

	startTime := time.Now()
	log.Info().Msgf("Starting port scan on %d IPs", len(ips))

	// Define scanner options
	opts := []func(*nmap.Scanner){
		nmap.WithTargets(ips...),
		// nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithCustomArguments(
			"-T3",
			"--min-parallelism", "75",
			"--max-parallelism", "150",
			"--max-retries", "2",
			"--host-timeout", "200s",
			"--source-port", "53",
			"--randomize-hosts",
		),
	}

	// Configure ports to scan
	if portsToScan != "" {
		// Use custom ports if specified
		opts = append(opts, nmap.WithPorts(portsToScan))
		log.Info().Msgf("Using custom ports for scan: %s", portsToScan)
	} else {
		// Otherwise use top 500 ports
		commonPorts := "80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,1049,1048,2967,1053,3703,1056,1065,1064,1054,17,808,3689,1031,1044,1071,5901,100,9102,8010,2869,1039,5120,4001,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1993,1761,5003,2002,2005,1998,1032,1050,6112,3690,1521,2161,6002,1080,2401,4045,902,7937,787,1058,2383,32771,1033,1040,1059,50000,5555,10001,1494,593,2301,3,1,3268,7938,1234,1022,1074,8002,1036,1035,9001,1037,464,497,1935,6666,2003,6543,1352,24,3269,1111,407,500,20,2006,3260,15000,1218,1034,4444,264,2004,33,1042,42510,999,3052,1023,1068,222,7100,888,4827,1999,563,1717,2008,992,32770,32772,7001,8082,2007,740,5550,2009,5801,1043,512,2701,7019,50001,1700,4662,2065,2010,42,9535,2602,3333,161,5100,5002,2604,4002,6059,1047,8192,8193,2702,6789,9595,1051,9594,9593,16993,16992,5226,5225,32769,3283,1052,8194,1055,1062,9415,8701,8652,8651,8089,65389,65000,64680,64623,55600,55555,52869,35500,33354,23502,20828,1311,1060,4443,730,731,709,1067,13782,5902,366,9050,1002,85,5500,5431,1864,1863,8085,51103,49999,45100,10243,49,3495,6667,90,475,27000,1503,6881,1500,8021,340,78,5566,8088,2222,9071,8899,6005,9876,1501,5102,32774,32773,9101,5679,163,648,146,1666,901,83,9207,8001,8083,5004,3476,8084,5214,14238,12345,912,30,2605,2030,6,541,8007,3005,4,1248,2500,880,306,4242,1097,9009,2525,1086,1088,8291,52822,6101,900,7200,2809,395,800,32775,12000,1083,211,987,705,20005,711,13783,6969,3071,5269,5222,1085,1046,5987,5989,5988,2190,11967,8600,3766,7627,8087,30000,9010,7741,14000,3367,1099,1098,3031,2718,6580,15002,4129,6901,3827,3580,2144,9900,8181,3801,1718,2811,9080,2135,1045,2399,3017,10002,1148,9002,8873,2875,9011,5718,8086,3998,2607,11110,4126,5911,5910,9618,2381,1096,3300,3351,1073,8333,3784,5633,15660,6123,3211,1078,3659,3551,2260,2160,2100,16001,3325,3323,1104,9968,9503,9502,9485,9290,9220,8994,8649,8222,7911,7625,7106,65129,63331,6156,6129,60020,5962,5961,5960,5959,5925,5877,5825,5810,58080,57294,50800"
		opts = append(opts, nmap.WithPorts(commonPorts))
		log.Info().Msg("Using 500 most common ports for scan")
	}

	// Add scan-type specific options
	if useSYNScan {
		opts = append([]func(*nmap.Scanner){nmap.WithSYNScan()}, opts...)
		log.Debug().Msg("Using SYN scan")
	} else {
		opts = append([]func(*nmap.Scanner){nmap.WithConnectScan()}, opts...)
		log.Debug().Msg("Using Connect scan")
	}

	// Calculate estimated scan time
	numPorts := countPorts(portsToScan)
	estimatedTimePerIP := estimateScanTime(numPorts)
	estimatedTotalTime := time.Duration(len(ips)) * estimatedTimePerIP

	if detailedIPLogs {
		log.Info().Msgf("Estimated scan time: %s for %d IPs (%s per IP)",
			formatDuration(estimatedTotalTime), len(ips), formatDuration(estimatedTimePerIP))
	}

	// Run the scan
	scanner, err := nmap.NewScanner(opts...)
	if err != nil {
		log.Error().Msgf("Error creating port scanner: %v", err)
		return discovered
	}

	scanStart := time.Now()
	scanResult, warnings, err := scanner.Run()
	scanDuration := time.Since(scanStart)

	if detailedIPLogs {
		if len(ips) > 0 {
			avgTimePerIP := scanDuration / time.Duration(len(ips))
			log.Info().Msgf("Port scan took %s total (%s avg per IP)",
				formatDuration(scanDuration), formatDuration(avgTimePerIP))
		} else {
			log.Info().Msgf("Port scan took %s total", formatDuration(scanDuration))
		}
	}

	if warnings != nil {
		log.Debug().Msgf("Port scan warnings: %v", warnings)
	}

	if err != nil {
		log.Error().Msgf("Port scan error: %v", err)
	} else if scanResult != nil {
		// Log detailed host information with timing
		if detailedIPLogs {
			log.Info().Msgf("Scan completed with %d hosts in results from %d IPs scanned (%d%% success rate)",
				len(scanResult.Hosts), len(ips), calculateSuccessRate(len(scanResult.Hosts), len(ips)))

			// Log IPs that may have timed out or failed
			if len(scanResult.Hosts) < len(ips) {
				foundIPs := make(map[string]bool)
				for _, host := range scanResult.Hosts {
					ip := ExtractIP(host)
					if ip != "" {
						foundIPs[ip] = true
					}
				}

				missingCount := 0
				for _, ip := range ips {
					if !foundIPs[ip] {
						missingCount++
						if missingCount <= 10 { // Limit the logging to first 10 missing IPs
							log.Info().Msgf("IP %s was not scanned successfully or timed out", ip)
						}
					}
				}

				if missingCount > 10 {
					log.Info().Msgf("... and %d more IPs were not scanned successfully", missingCount-10)
				}
			}
		}

		// Show detailed timing per host
		if detailedIPLogs {
			log.Info().Msgf("Processing scan results for %d hosts", len(scanResult.Hosts))
		}

		// Process the scan results
		hostCount := 0
		hostsWithPorts := 0
		totalPortsFound := 0

		for _, host := range scanResult.Hosts {
			hostCount++

			if strings.ToLower(host.Status.State) == "up" && HasOpenPorts(host) {
				ip := ExtractIP(host)
				if ip != "" {
					discovered[ip] = host

					// Extract and log open ports
					var openPorts []int
					for _, port := range host.Ports {
						if strings.ToLower(port.State.State) == "open" {
							openPorts = append(openPorts, int(port.ID))
						}
					}

					if len(openPorts) > 0 {
						hostsWithPorts++
						totalPortsFound += len(openPorts)

						sort.Ints(openPorts)
						portsStr := FormatOpenPorts(openPorts)
						log.Info().Msgf("Host %s has open ports: %s", ip, portsStr)
					}
				}
			}
		}

		// Log summary statistics
		if detailedIPLogs && hostCount > 0 {
			portsPerHost := float64(totalPortsFound) / float64(hostsWithPorts)
			successRate := calculateSuccessRate(hostsWithPorts, hostCount)

			log.Info().Msgf("Port scan stats: %d/%d hosts have open ports (%.1f%%), avg %.1f ports per host with ports",
				hostsWithPorts, hostCount, float64(hostsWithPorts)/float64(hostCount)*100, portsPerHost)

			log.Info().Msgf("Scan success rate: %d%% (%d hosts processed out of %d attempted)",
				successRate, hostCount, len(ips))
		}
	}

	totalDuration := time.Since(startTime)
	log.Info().Msgf("Port scan complete. Discovered %d hosts with open ports in %s.",
		len(discovered), formatDuration(totalDuration))

	return discovered
}

// countPorts returns the number of ports in a port specification
func countPorts(portsSpec string) int {
	if portsSpec == "" {
		// Default is 500 ports
		return 500
	}

	// Split by commas and count
	ports := strings.Split(portsSpec, ",")
	return len(ports)
}

// estimateScanTime estimates scan time per IP based on number of ports
func estimateScanTime(numPorts int) time.Duration {
	// Simple model: base time + per port time
	baseTime := 5 * time.Second
	perPortTime := 100 * time.Millisecond

	return baseTime + time.Duration(numPorts)*perPortTime
}

// formatDuration formats a duration in a human-readable form
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)

	if d < time.Minute {
		return fmt.Sprintf("%ds", d.Seconds())
	} else if d < time.Hour {
		m := d / time.Minute
		s := (d % time.Minute) / time.Second
		return fmt.Sprintf("%dm%ds", m, s)
	} else {
		h := d / time.Hour
		m := (d % time.Hour) / time.Minute
		s := (d % time.Minute) / time.Second
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
}

// calculateSuccessRate calculates success rate as a percentage
func calculateSuccessRate(processed, attempted int) int {
	if attempted == 0 {
		return 0
	}
	return int((float64(processed) / float64(attempted)) * 100)
}

// isHostManageable checks if a host has any management ports open
func isHostManageable(hostPorts []int, managementPorts []int) bool {
	for _, port := range hostPorts {
		for _, mgmtPort := range managementPorts {
			if port == mgmtPort {
				return true
			}
		}
	}
	return false
}

// convertDiscoveredToResults transforms the map of discovered hosts into a slice of HostResult.
func convertDiscoveredToResults(discovered map[string]nmap.Host, dnsServer string) []HostResult {
	var results []HostResult
	for ip, host := range discovered {
		dnsName := ""
		if dnsServer != "" {
			names, err := customLookupAddr(ip, dnsServer)
			if err == nil && len(names) > 0 {
				dnsName = names[0]
			}
		} else if len(host.Hostnames) > 0 && host.Hostnames[0].Name != "" {
			dnsName = host.Hostnames[0].Name
		} else {
			names, err := net.LookupAddr(ip)
			if err == nil && len(names) > 0 {
				dnsName = strings.TrimSuffix(names[0], ".")
			}
		}

		// Extract open ports from nmap scan results
		var openPorts []int
		for _, port := range host.Ports {
			if strings.ToLower(port.State.State) == "open" {
				openPorts = append(openPorts, int(port.ID))
			}
		}
		sort.Ints(openPorts)

		// Create the host result
		results = append(results, HostResult{
			Address: ip,
			DnsName: dnsName,
			Status:  "active",
			CustomFields: map[string]interface{}{
				"scantime": time.Now().Format(time.RFC3339),
			},
			OpenPorts: openPorts,
		})
	}
	return results
}

// FormatOpenPorts converts a slice of port numbers to a comma-separated string
func FormatOpenPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = fmt.Sprintf("%d", port)
	}

	return strings.Join(portStrings, ",")
}

// customLookupAddr performs a reverse DNS lookup using a specified DNS server
func customLookupAddr(ip, dnsServer string) ([]string, error) {
	// Convert IP to its reverse lookup format.
	reverse, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("error generating reverse address for %s: %v", ip, err)
	}

	// Create a DNS message with a PTR query.
	m := new(dns.Msg)
	m.SetQuestion(reverse, dns.TypePTR)

	// Create a DNS client and send the query to the specified DNS server.
	c := new(dns.Client)
	// Optionally set a timeout:
	// c.Timeout = 2 * time.Second
	resp, _, err := c.Exchange(m, dnsServer)
	if err != nil {
		// Return immediately if there's an error.
		return nil, fmt.Errorf("DNS query error for %s: %v", dnsServer, err)
	}

	// Check if resp is nil before accessing resp.Answer.
	if resp == nil {
		return nil, fmt.Errorf("DNS query returned nil response for %s", dnsServer)
	}

	// Process the response and extract the names.
	var names []string
	for _, answer := range resp.Answer {
		if ptr, ok := answer.(*dns.PTR); ok {
			// Remove the trailing dot from the name if present.
			names = append(names, strings.TrimSuffix(ptr.Ptr, "."))
		}
	}
	return names, nil
}

// ExtractIP extracts the IPv4 address from a host.
func ExtractIP(host nmap.Host) string {
	for _, addr := range host.Addresses {
		if strings.ToLower(addr.AddrType) == "ipv4" {
			return addr.Addr
		}
	}
	if len(host.Addresses) > 0 {
		return host.Addresses[0].Addr
	}
	return ""
}

// GenerateIPs generates all IPv4 addresses for a given CIDR block, excluding network and broadcast addresses.
func GenerateIPs(cidr string) []string {
	var ips []string
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Error().Msgf("Error parsing CIDR in GenerateIPs: %v", err)
		return ips
	}
	current := ip.Mask(ipNet.Mask).To4()
	for ipNet.Contains(current) {
		ips = append(ips, current.String())
		current = IncIP(current)
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

// IncIP increments an IPv4 address.
func IncIP(ip net.IP) net.IP {
	ip = append(net.IP(nil), ip...)
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
	return ip
}

// SubdivideTo24 divides an IP block into /24 subnets.
func SubdivideTo24(ipNet *net.IPNet) []string {
	var subnets []string
	ones, _ := ipNet.Mask.Size()
	if ones >= 24 {
		subnets = append(subnets, ipNet.String())
		return subnets
	}
	increment := uint32(1 << (32 - 24))
	startIP := ipNet.IP.To4()
	if startIP == nil {
		log.Fatal().Msg("Cannot convert IP to IPv4")
	}
	start := binary.BigEndian.Uint32(startIP)
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	end := start | ^mask
	for addr := start; addr <= end; addr += increment {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, addr)
		_, subnet, _ := net.ParseCIDR(fmt.Sprintf("%s/24", ip.String()))
		if ipNet.Contains(subnet.IP) {
			subnets = append(subnets, subnet.String())
		}
	}
	return subnets
}

// HasOpenPorts checks if a host has any open ports.
func HasOpenPorts(host nmap.Host) bool {
	for _, port := range host.Ports {
		if port.State.State == "open" {
			return true
		}
	}
	return false
}

// PrettyJSON returns a formatted JSON string.
func PrettyJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}
