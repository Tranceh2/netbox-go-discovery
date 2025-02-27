package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tranceh2/netbox-go-discovery/pkg/config"
	"github.com/tranceh2/netbox-go-discovery/pkg/logger"
	"github.com/tranceh2/netbox-go-discovery/pkg/metrics"
	"github.com/tranceh2/netbox-go-discovery/pkg/netboxclient"
	"github.com/tranceh2/netbox-go-discovery/pkg/scanner"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	cron "github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"

	netbox "github.com/netbox-community/go-netbox/v4"
)

// main is the entry point of the application. It initializes configuration,
// sets up signal handling, starts the HTTP server for metrics, and manages
// the scanning process both for initial and scheduled scans.
func main() {
	// Load configuration from environment variables
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Msgf("Error loading configuration: %v", err)
	}
	logger.InitLogger(cfg.LogFormat, cfg.Verbose)
	metrics.InitMetrics()

	// Create context for signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info().Msgf("Received signal %s, shutting down...", sig)
		cancel()
	}()

	// Start HTTP server for healthcheck and metrics
	go startHTTPServer(ctx, cfg.HealthPort)

	// Initialize NetBox client
	netboxcfg := netbox.NewConfiguration()
	netboxcfg.Servers[0].URL = cfg.NetboxHost
	netboxcfg.AddDefaultHeader("Authorization", "Token "+cfg.NetboxToken)
	netboxcfg.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.SkipCertVerify,
			},
		},
	}
	apiClient := netbox.NewAPIClient(netboxcfg)

	// Configure cron for scheduled scans
	c := cron.New(cron.WithLogger(cron.VerbosePrintfLogger(&logger.ZerologCronLogger{Logger: log.Logger})))
	_, err = c.AddFunc(cfg.CronSchedule, func() {
		metrics.ScanRuns.Inc()
		startTime := time.Now()
		log.Info().Msg("Starting scheduled scan...")
		results, subnetSummary, err := scanner.RunScan(ctx, cfg.TargetRange, cfg.ConcurrencyLimit, cfg.DetailedIPLogs, cfg.DnsServer, cfg.UseSYNScan)
		if err != nil {
			log.Error().Msgf("Error during scan: %v", err)
		} else {
			log.Info().Msgf("Scan complete. Discovered %d hosts.", len(results))
			processNetBox(apiClient, results, cfg)
			printSummary(subnetSummary, results, startTime)
		}
		metrics.ScanDuration.Observe(time.Since(startTime).Seconds())
	})
	if err != nil {
		log.Fatal().Msgf("Error setting up cron: %v", err)
	}
	c.Start()

	// Perform initial immediate scan
	go func() {
		log.Info().Msg("Starting initial scan...")
		metrics.ScanRuns.Inc()
		startTime := time.Now()
		results, subnetSummary, err := scanner.RunScan(ctx, cfg.TargetRange, cfg.ConcurrencyLimit, cfg.DetailedIPLogs, cfg.DnsServer, cfg.UseSYNScan)
		if err != nil {
			log.Error().Msgf("Initial scan error: %v", err)
		} else {
			log.Info().Msgf("Initial scan complete. Discovered %d hosts.", len(results))
			processNetBox(apiClient, results, cfg)
			printSummary(subnetSummary, results, startTime)
		}
		metrics.ScanDuration.Observe(time.Since(startTime).Seconds())
	}()

	<-ctx.Done()
	log.Info().Msg("Shutting down application...")
	c.Stop()
}

// processNetBox handles the synchronization of scan results with NetBox.
// It creates new IP entries, updates existing ones, and marks as deprecated
// those that are no longer detected. It also updates relevant metrics.
func processNetBox(apiClient *netbox.APIClient, results []scanner.HostResult, cfg *config.Config) {
	// Query NetBox to get the registered IPs
	nbIPs, err := netboxclient.GetNetboxIPs(apiClient, cfg.TargetRange)
	if err != nil {
		log.Error().Msgf("Error querying NetBox: %v", err)
		return
	}

	// Create maps for efficient lookups
	netboxMap := make(map[string]*netbox.IPAddress)
	for _, nbip := range nbIPs {
		ipOnly := splitIP(nbip.Address)
		netboxMap[ipOnly] = &nbip
	}

	scannedMap := make(map[string]scanner.HostResult)
	for _, h := range results {
		scannedMap[h.Address] = h
	}

	var createdCount, updatedCount, deprecatedCount int
	// Process IP addresses: create new ones or update existing ones
	for ip, host := range scannedMap {
		if nbip, exists := netboxMap[ip]; exists {
			err := netboxclient.UpdateNetboxIP(apiClient, host.Address, host.DnsName, host.Status, host.CustomFields, nbip.Id, cfg.VRFName, cfg.PreserveDNS)
			if err != nil {
				log.Error().Msgf("Error updating IP %s: %v", ip, err)
			} else {
				updatedCount++
				if cfg.DetailedIPLogs {
					log.Info().Msgf("IP %s updated in NetBox.", ip)
				}
			}
		} else {
			err := netboxclient.CreateNetboxIP(apiClient, host.Address, host.DnsName, host.Status, host.CustomFields, cfg.VRFName)
			if err != nil {
				log.Error().Msgf("Error creating IP %s: %v", ip, err)
			} else {
				createdCount++
				if cfg.DetailedIPLogs {
					log.Info().Msgf("IP %s created in NetBox.", ip)
				}
			}
		}
	}

	// Handle deprecation of IPs not found in current scan
	for ip, nbip := range netboxMap {
		if _, exists := scannedMap[ip]; !exists {
			lastSeen, err := netboxclient.ParseScanTime(nbip)
			if err != nil {
				lastSeen = time.Now().Add(-cfg.DeprecationThreshold - time.Hour)
			}
			if time.Since(lastSeen) > cfg.DeprecationThreshold {
				log.Info().Msgf("Marking IP %s as deprecated.", ip)
				err := netboxclient.MarkNetboxIPDeprecated(apiClient, nbip.Id)
				if err != nil {
					log.Error().Msgf("Error deprecating IP %s: %v", ip, err)
				} else {
					deprecatedCount++
				}
			}
		}
	}

	// Update metrics and log results
	metrics.IpsCreated.Add(float64(createdCount))
	metrics.IpsUpdated.Add(float64(updatedCount))
	metrics.IpsDeprecated.Add(float64(deprecatedCount))

	log.Info().Msgf("IPs created in NetBox: %d", createdCount)
	log.Info().Msgf("IPs updated in NetBox: %d", updatedCount)
	log.Info().Msgf("IPs deprecated in NetBox: %d", deprecatedCount)
}

// printSummary outputs a formatted summary of the scan results,
// including the number of hosts detected per subnet and total scan duration.
func printSummary(subnetSummary map[string]int, results []scanner.HostResult, startTime time.Time) {
	var sortedSubnets []string
	for subnet := range subnetSummary {
		sortedSubnets = append(sortedSubnets, subnet)
	}
	sort.Strings(sortedSubnets)
	log.Info().Msg("---------- Scan Summary ----------")
	for _, subnet := range sortedSubnets {
		log.Info().Msgf("Subnet %s: %d host(s) detected", subnet, subnetSummary[subnet])
	}
	log.Info().Msgf("Total scan completed in: %s", time.Since(startTime))
}

// startHTTPServer initializes and runs the HTTP server for health checks
// and metrics endpoints. It gracefully shuts down when the context is cancelled.
func startHTTPServer(ctx context.Context, port string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			log.Error().Err(err).Msg("failed to write healthz response")
		}
	})
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	go func() {
		<-ctx.Done()
		log.Info().Msg("Shutting down HTTP server...")
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Error().Err(err).Msg("failed to shutdown HTTP server")
		}
	}()
	log.Info().Msgf("HTTP server listening on port %s", port)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Msgf("HTTP server error: %v", err)
	}
}

// splitIP extracts the IP address from a CIDR notation string
// by removing the subnet mask if present.
func splitIP(address string) string {
	parts := strings.Split(address, "/")
	return parts[0]
}