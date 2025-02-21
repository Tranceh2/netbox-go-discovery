package scanner

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
}

// SubnetScanResult stores the result of a scan on a subnet.
type SubnetScanResult struct {
	Subnet string       // Subnet in CIDR notation.
	Hosts  []HostResult // List of hosts discovered in the subnet.
}

// RunScan executes the scan process on the targetRange using concurrency.
// It divides the target range into smaller subnets (/24) if the range is larger than a /24.
// It returns a slice of HostResult, a map summarizing the number of hosts per subnet, and an error if any.
func RunScan(ctx context.Context, targetRange string, concurrencyLimit int, detailedIPLogs bool, dnsServer string, useSYNScan bool) ([]HostResult, map[string]int, error) {
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
			results := RunHostDiscovery(target, detailedIPLogs, dnsServer, useSYNScan)
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

// runPingScan performs a quick ping scan and returns a map of discovered IPs.
func runPingScan(target string, detailedIPLogs bool) map[string]nmap.Host {
	discovered := make(map[string]nmap.Host)
	log.Info().Msgf("Starting quick ping scan on target: %s", target)
	pingScanner, err := nmap.NewScanner(
		nmap.WithTargets(target),
		nmap.WithPingScan(),
		nmap.WithSYNDiscovery(),
		nmap.WithACKDiscovery(),
		nmap.WithICMPEchoDiscovery(),
		nmap.WithICMPTimestampDiscovery(),
		nmap.WithHostTimeout(6*time.Second),
	)
	if err != nil {
		log.Fatal().Msgf("Error creating ping scan: %v", err)
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
						log.Info().Msgf("Host %s discovered during quick ping scan.", ip)
					}
				}
			}
		}
	}
	return discovered
}

// runFallbackScan performs a fallback scan on IPs that did not respond to the ping scan.
// The scan type is determined by the useSYNScan flag: if true, a SYN scan is used; otherwise, a Connect scan is performed.
// It updates the "discovered" map with any newly discovered hosts.
func runFallbackScan(target string, discovered map[string]nmap.Host, detailedIPLogs bool, useSYNScan bool) {
	allIPs := GenerateIPs(target)
	var fallbackIPs []string
	for _, ip := range allIPs {
		if _, found := discovered[ip]; !found {
			fallbackIPs = append(fallbackIPs, ip)
		}
	}

	if len(fallbackIPs) == 0 {
		return
	}

	var scanType string
	if useSYNScan {
		scanType = "SYN scan"
	} else {
		scanType = "TCP connect scan"
	}
	log.Info().Msgf("Starting fallback %s on %d IPs that did not respond to ping scan.", scanType, len(fallbackIPs))

	// Define common scanner options as a slice of functions.
	opts := []func(*nmap.Scanner){
		nmap.WithTargets(fallbackIPs...),
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithCustomArguments(
			"-T3",
			"--min-parallelism", "50",
			"--max-parallelism", "100",
			"--max-retries", "3",
			"--host-timeout", "5s",
			"--randomize-hosts",
		),
		nmap.WithMostCommonPorts(1000),
	}

	// Add scan-type specific options.
	if useSYNScan {
		opts = append([]func(*nmap.Scanner){nmap.WithSYNScan()}, opts...)
	} else {
		opts = append([]func(*nmap.Scanner){nmap.WithConnectScan()}, opts...)
	}

	fallbackScanner, err := nmap.NewScanner(opts...)
	if err != nil {
		log.Fatal().Msgf("Error creating fallback %s scanner: %v", scanType, err)
	}

	fallbackResult, fbWarnings, err := fallbackScanner.Run()
	if fbWarnings != nil {
		log.Debug().Msgf("Fallback %s warnings: %v", scanType, fbWarnings)
	}
	if err != nil {
		log.Error().Msgf("Fallback %s error: %v", scanType, err)
	} else if fallbackResult != nil {
		for _, host := range fallbackResult.Hosts {
			if strings.ToLower(host.Status.State) == "up" && HasOpenPorts(host) {
				ip := ExtractIP(host)
				if ip != "" {
					discovered[ip] = host
					if detailedIPLogs {
						log.Info().Msgf("Host %s discovered during fallback %s.", ip, scanType)
					}
				}
			}
		}
	}
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
		results = append(results, HostResult{
			Address: ip,
			DnsName: dnsName,
			Status:  "active",
			CustomFields: map[string]interface{}{
				"scantime": time.Now().Format(time.RFC3339),
			},
		})
	}
	return results
}

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

// RunHostDiscovery performs host discovery combining both phases.
func RunHostDiscovery(target string, detailedIPLogs bool, dnsServer string, useSYNScan bool) []HostResult {
	discovered := runPingScan(target, detailedIPLogs)
	runFallbackScan(target, discovered, detailedIPLogs, useSYNScan)
	return convertDiscoveredToResults(discovered, dnsServer)
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
		if port.State.State == "open" && ConfirmOpenPort(ExtractIP(host), int(port.ID)) {
			return true
		}
	}
	return false
}

// ConfirmOpenPort verifies if a port is open by attempting a TCP connection (and optionally an HTTP request).
func ConfirmOpenPort(ip string, port int) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		resp, err := http.Get(fmt.Sprintf("http://%s", target))
		if err == nil && resp.StatusCode < 500 {
			return true
		}
		return true
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
