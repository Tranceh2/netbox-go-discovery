package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metrics definitions
var (
	// ScanRuns tracks the total number of network scans performed
	ScanRuns = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "scan_runs_total",
		Help: "Total number of network scans executed.",
	})

	// ScanDuration measures the duration of each network scan
	ScanDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "scan_duration_seconds",
		Help:    "Duration of network scans in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	// IpsCreated counts the number of IP addresses created in NetBox
	IpsCreated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ips_created_total",
		Help: "Total number of IP addresses created in NetBox.",
	})

	// IpsUpdated tracks the number of IP addresses updated in NetBox
	IpsUpdated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ips_updated_total",
		Help: "Total number of IP addresses updated in NetBox.",
	})

	// IpsDeprecated counts the number of IP addresses marked as deprecated in NetBox
	IpsDeprecated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ips_deprecated_total",
		Help: "Total number of IP addresses marked as deprecated in NetBox.",
	})

	// HostsDetected shows the current number of hosts found in the last scan
	HostsDetected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "hosts_detected",
		Help: "Number of hosts detected in the last network scan.",
	})

	// SubnetScanDuration measures the scan duration per subnet
	SubnetScanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "subnet_scan_duration_seconds",
			Help:    "Duration of network scans per subnet in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"subnet"},
	)

	// ScanSuccessFailure counts successful and failed scans
	ScanSuccessFailure = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "scan_results_total",
			Help: "Total number of network scans by result (success/failure).",
		},
		[]string{"result"},
	)

	// OpenPortsDetected counts the total number of open ports detected
	OpenPortsDetected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "open_ports_detected_total",
		Help: "Total number of open ports detected across all hosts.",
	})

	// ManageableDevices shows the number of manageable devices found in the last scan
	ManageableDevices = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "manageable_devices",
		Help: "Number of manageable devices detected in the last network scan.",
	})
)

// InitMetrics registers all metrics with Prometheus.
// This function must be called before using any metrics.
func InitMetrics() {
	prometheus.MustRegister(
		ScanRuns, 
		ScanDuration, 
		IpsCreated, 
		IpsUpdated, 
		IpsDeprecated, 
		HostsDetected,
		SubnetScanDuration,
		ScanSuccessFailure,
		OpenPortsDetected,
		ManageableDevices,
	)
}
