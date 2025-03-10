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
	"github.com/tranceh2/netbox-go-discovery/pkg/metrics"
)

type PortInfo struct {
	Number   int    `json:"number"`   // Numeric port
	Protocol string `json:"protocol"` // Protocol (tcp, udp, etc.)
}

// HostResult represents the information of a detected host.
type HostResult struct {
	Address      string                 `json:"address"`       // IP address of the host.
	DnsName      string                 `json:"dns_name"`      // DNS name of the host, if available.
	Status       string                 `json:"status"`        // Host status (e.g., "active").
	CustomFields map[string]interface{} `json:"custom_fields"` // Custom fields associated with the host.
	OpenPorts    []PortInfo             `json:"open_ports"`    // List of open ports with protocol.
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
		metrics.ScanSuccessFailure.WithLabelValues("failure").Inc()
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
			metrics.ScanSuccessFailure.WithLabelValues("failure").Inc()
			return nil, nil, nil
		default:
		}
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			semaphore <- struct{}{}
			log.Info().Msgf("Starting discovery on subnet %s (%d/%d)", target, idx+1, len(targets))

			startTime := time.Now()

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

			// Record subnet scan duration
			duration := time.Since(startTime).Seconds()
			metrics.SubnetScanDuration.WithLabelValues(target).Observe(duration)

			log.Info().Msgf("Discovery complete on subnet %s: %d hosts detected in %.2f seconds",
				target, len(results), duration)
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

	metrics.ScanSuccessFailure.WithLabelValues("success").Inc()
	metrics.HostsDetected.Set(float64(len(overallResults)))

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
		manageableCount := 0
		for i := range results {
			isManageable := isHostManageable(results[i].OpenPorts, managementPorts)
			results[i].CustomFields[manageableField] = isManageable

			if isManageable {
				manageableCount++
				if detailedIPLogs {
					log.Info().Msgf("Host %s is remotely manageable", results[i].Address)
				}
			}
		}

		// Update the manageable devices metric
		metrics.ManageableDevices.Set(float64(manageableCount))
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

// runPortScan performs a port scan on the specified IPs
func runPortScan(ips []string, detailedIPLogs bool, useSYNScan bool, portsToScan string) map[string]nmap.Host {
	discovered := make(map[string]nmap.Host)

	if len(ips) == 0 {
		return discovered
	}

	log.Info().Msgf("Starting port scan on %d IPs", len(ips))

	// Define scanner options
	opts := []func(*nmap.Scanner){
		nmap.WithTargets(ips...),
		// nmap.WithSkipHostDiscovery(),
		nmap.WithOpenOnly(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithUDPScan(),
		nmap.WithCustomArguments(
			"-T4",
			"--min-parallelism", "80",
			"--max-parallelism", "180",
			"--max-retries", "1",
			"--host-timeout", "400s",
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
		opts = append(opts, nmap.WithMostCommonPorts(500))
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

	// Run the scan
	scanner, err := nmap.NewScanner(opts...)
	if err != nil {
		log.Error().Msgf("Error creating port scanner: %v", err)
		return discovered
	}

	scanResult, warnings, err := scanner.Run()
	if warnings != nil {
		log.Debug().Msgf("Port scan warnings: %v", warnings)
	}

	if err != nil {
		log.Error().Msgf("Port scan error: %v", err)
	} else if scanResult != nil {
		for _, host := range scanResult.Hosts {
			if strings.ToLower(host.Status.State) == "up" && HasOpenPorts(host) {
				ip := ExtractIP(host)
				if ip != "" {
					discovered[ip] = host

					// Extract and log open ports with protocol
					var openPortsInfo []PortInfo
					for _, port := range host.Ports {
						if strings.ToLower(port.State.State) == "open" {
							protocol := strings.ToLower(port.Protocol)
							if protocol == "" {
								protocol = "tcp"
							}

							openPortsInfo = append(openPortsInfo, PortInfo{
								Number:   int(port.ID),
								Protocol: protocol,
							})
						}
					}

					if len(openPortsInfo) > 0 {
						// Sort by port number
						sort.Slice(openPortsInfo, func(i, j int) bool {
							return openPortsInfo[i].Number < openPortsInfo[j].Number
						})

						// Convert to string with "port/protocol" format
						portDetailsStr := make([]string, len(openPortsInfo))
						for i, p := range openPortsInfo {
							portDetailsStr[i] = fmt.Sprintf("%d/%s", p.Number, p.Protocol)
						}

						portsStr := strings.Join(portDetailsStr, ",")
						if detailedIPLogs {
							log.Info().Msgf("Host %s has open ports: %s", ip, portsStr)
						}
					}
				}
			}
		}
	}

	log.Info().Msgf("Port scan complete. Discovered %d hosts with open ports.", len(discovered))
	return discovered
}

// isHostManageable checks if a host has any management ports open
func isHostManageable(hostPorts []PortInfo, managementPorts []int) bool {
	for _, port := range hostPorts {
		for _, mgmtPort := range managementPorts {
			if port.Number == mgmtPort {
				return true
			}
		}
	}
	return false
}

// convertDiscoveredToResults transforms the map of discovered hosts into a slice of HostResult.
func convertDiscoveredToResults(discovered map[string]nmap.Host, dnsServer string) []HostResult {
	var results []HostResult
	var totalOpenPorts int

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

		// Extract open ports and protocol from nmap results
		var openPorts []PortInfo
		for _, port := range host.Ports {
			if strings.ToLower(port.State.State) == "open" {
				// Extract the protocol, defaulting to "tcp" if not specified
				protocol := strings.ToLower(port.Protocol)
				if protocol == "" {
					protocol = "tcp"
				}

				openPorts = append(openPorts, PortInfo{
					Number:   int(port.ID),
					Protocol: protocol,
				})

				// Count each open port for metrics
				totalOpenPorts++
			}
		}

		// Sort by port number
		sort.Slice(openPorts, func(i, j int) bool {
			return openPorts[i].Number < openPorts[j].Number
		})

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

	// Increment the open ports metric
	metrics.OpenPortsDetected.Add(float64(totalOpenPorts))

	return results
}

// FormatOpenPorts converts a slice of PortInfo to a comma-separated string with format "port/protocol"
func FormatOpenPorts(ports []PortInfo) string {
	if len(ports) == 0 {
		return ""
	}

	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = fmt.Sprintf("%d/%s", port.Number, port.Protocol)
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
