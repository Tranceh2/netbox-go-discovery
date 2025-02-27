package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds the application configuration settings.
// It centralizes all the configuration parameters needed for the application to run.
type Config struct {
	// TargetRange specifies the IP range to scan.
	TargetRange string
	// NetboxHost is the URL of the NetBox instance.
	NetboxHost string
	// NetboxToken is the authentication token for NetBox API.
	NetboxToken string
	// ConcurrencyLimit defines the maximum number of concurrent operations.
	ConcurrencyLimit int
	// Verbose enables detailed logging output.
	Verbose bool
	// DetailedIPLogs enables comprehensive IP scanning logs.
	DetailedIPLogs bool
	// LogFormat specifies the format of logs (e.g., "text", "json").
	LogFormat string
	// HealthPort defines the port for health check endpoint.
	HealthPort string
	// CronSchedule specifies when the scanning job should run.
	CronSchedule string
	// DeprecationThreshold is the duration after which an IP is considered deprecated.
	DeprecationThreshold time.Duration
	// SkipCertVerify disables TLS certificate verification for NetBox. Use with caution.
	SkipCertVerify bool
	// DnsServer specifies the DNS server address to use for reverse DNS lookups.
	DnsServer string
	// UseSYNScan specifies whether to use SYN scan for IP discovery
	UseSYNScan bool
	// VRFName specifies the VRF name to associate with discovered IPs (optional)
	VRFName string
	// PreserveDNS determines if existing DNS names should be preserved during updates
	PreserveDNS bool
}

// LoadConfig reads configuration from environment variables and returns a new Config instance.
// It sets default values for optional parameters and validates required ones.
// Returns an error if required environment variables are not set.
func LoadConfig() (*Config, error) {
	concurrency := 50
	if v := os.Getenv("CONCURRENCY_LIMIT"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &concurrency); err != nil {
			return nil, fmt.Errorf("failed to parse CONCURRENCY_LIMIT: %w", err)
		}
	}
	healthPort := "8080"
	if v := os.Getenv("HEALTH_PORT"); v != "" {
		healthPort = v
	}
	cronSchedule := os.Getenv("CRON_SCHEDULE")
	if cronSchedule == "" {
		cronSchedule = "0 0 * * *" // Daily execution at midnight
	}
	verbose := strings.ToLower(os.Getenv("VERBOSE")) == "true"
	detailedIPLogs := strings.ToLower(os.Getenv("DETAILED_IP_LOGS")) == "true"
	logFormat := os.Getenv("LOG_FORMAT")
	if logFormat == "" {
		logFormat = "text"
	}

	targetRange := os.Getenv("TARGET_RANGE")
	if targetRange == "" {
		return nil, fmt.Errorf("TARGET_RANGE environment variable is not defined")
	}
	netboxHost := os.Getenv("NETBOX_HOST")
	netboxToken := os.Getenv("NETBOX_TOKEN")
	if netboxHost == "" || netboxToken == "" {
		return nil, fmt.Errorf("both NETBOX_HOST and NETBOX_TOKEN environment variables must be defined")
	}

	deprecationThresholdStr := os.Getenv("DEPRECATION_THRESHOLD")
	if deprecationThresholdStr == "" {
		deprecationThresholdStr = "24h"
	}
	deprecationThreshold, err := time.ParseDuration(deprecationThresholdStr)
	if err != nil {
		return nil, fmt.Errorf("invalid DEPRECATION_THRESHOLD: %w", err)
	}
	skipCertVerify := strings.ToLower(os.Getenv("SKIP_CERT_VERIFY")) == "true"

	dnsServer := normalizeDNSServer(os.Getenv("DNS_SERVER"))

	useSYNScan := strings.ToLower(os.Getenv("SYN_SCAN")) == "true"
	
	vrfName := os.Getenv("VRF_NAME")
	
	preserveDNS := strings.ToLower(os.Getenv("PRESERVE_DNS")) == "true"

	return &Config{
		TargetRange:          targetRange,
		NetboxHost:           netboxHost,
		NetboxToken:          netboxToken,
		ConcurrencyLimit:     concurrency,
		Verbose:              verbose,
		DetailedIPLogs:       detailedIPLogs,
		LogFormat:            logFormat,
		HealthPort:           healthPort,
		CronSchedule:         cronSchedule,
		DeprecationThreshold: deprecationThreshold,
		SkipCertVerify:       skipCertVerify,
		DnsServer:            dnsServer,
		UseSYNScan:           useSYNScan,
		VRFName:              vrfName,
		PreserveDNS:          preserveDNS,
	}, nil
}

func normalizeDNSServer(dnsServer string) string {
	if dnsServer == "" {
		return ""
	}
	if !strings.Contains(dnsServer, ":") {
		// Append default DNS port
		dnsServer = dnsServer + ":53"
	}
	return dnsServer
}
