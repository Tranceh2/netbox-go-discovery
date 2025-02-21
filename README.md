# Netbox Go Discovery

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/tranceh2/netbox-go-discovery)](https://goreportcard.com/report/github.com/tranceh2/netbox-go-discovery)

Netbox Go Discovery is a tool that automatically discovers and manages IP addresses in your network and synchronizes them with your Netbox instance. It performs network scans, identifies active hosts, and updates Netbox accordingly—creating new IP entries, updating existing ones, and deprecating those that are no longer detected.

## Features

- **Automated Network Discovery:** Scans the network for active hosts using quick ping and fallback scans.
- **Netbox Synchronization:** Automatically creates, updates, and deprecates IP addresses in Netbox based on scan results.
- **Scheduled Scans:** Supports scheduled scans using cron expressions.
- **Configurable Deprecation Threshold:** Specify the duration after which an IP is considered deprecated (default: 24h).
- **Concurrency Control:** Limits the number of concurrent scan operations to avoid overloading the network.
- **Detailed Logging:** Provides detailed logs of the scan process, including discovered hosts and Netbox updates.
- **Prometheus Metrics:** Exposes Prometheus metrics for monitoring scan performance and Netbox synchronization.
- **Health Check Endpoint:** Includes a `/healthz` endpoint for monitoring the application's status.
- **Custom DNS Resolution:** Configure a custom DNS server for reverse DNS lookups by using the `DNS_SERVER` option.
- **SYN Scan Toggle:** Toggle between SYN scan and TCP connect scan for fallback scanning using the `SYN_SCAN` option, with logging that clearly indicates the type of scan being used.

## Getting Started

### Prerequisites

- Go 1.23 or higher
- A running Netbox instance
- Network access to the target range
- A custom field named `scantime` (Date and Time type) in Netbox, used to store the timestamp of the last scan for each IP address

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/tranceh2/netbox-go-discovery.git
   cd netbox-go-discovery
   ```

2. Build the application:

   ```bash
   go build -o netbox-go-discovery ./cmd/netbox-go-discovery
   ```

### Configuration

The application is configured via environment variables. The following variables are **required**:

- `TARGET_RANGE`: The IP range to scan (e.g., `192.168.1.0/24`).
- `NETBOX_HOST`: The URL of the Netbox instance (e.g., `https://netbox.example.com`).
- `NETBOX_TOKEN`: The authentication token for the Netbox API.

The following variables are **optional**:

- `CONCURRENCY_LIMIT`: Maximum number of concurrent scan operations (default: `50`).
- `VERBOSE`: Enable detailed logging output (default: `false`).
- `DETAILED_IP_LOGS`: Enable comprehensive IP scanning logs (default: `false`).
- `LOG_FORMAT`: Log format (`text` or `json`, default: `text`).
- `HEALTH_PORT`: Port for the health check endpoint (default: `8080`).
- `CRON_SCHEDULE`: Cron schedule for running scans (default: `0 0 * * *` – daily at midnight).
- `DEPRECATION_THRESHOLD`: The duration after which an IP is considered deprecated (e.g., `24h`; default is `24h`).
- `SKIP_CERT_VERIFY`: Skip SSL certificate verification (not recommended for production; default: `false`).
- **`DNS_SERVER`:** Specify a DNS server for reverse DNS lookups (e.g., `192.168.100.30:53`).
- **`SYN_SCAN`:** Toggle the fallback scan type. Set to `true` to use SYN scan, or `false` to use TCP connect scan (default: `false`).

### Usage

1. Set the environment variables. For example:

   ```bash
   export TARGET_RANGE="192.168.1.0/24"
   export NETBOX_HOST="https://netbox.example.com"
   export NETBOX_TOKEN="your_netbox_token"
   export DEPRECATION_THRESHOLD="24h"
   export DNS_SERVER="192.168.100.30:53"         # Optional: specify a DNS server for reverse DNS
   export SYN_SCAN="true"           # Optional: enable SYN scan for fallback scanning
   ```

2. Run the application:

   ```bash
   ./netbox-go-discovery
   ```

### Running with Docker

The Docker image is available on Docker Hub as `tranceh2/netbox-go-discovery`.

#### Basic Usage

Run the container with the required environment variables:

```bash
docker run -d \
  -e TARGET_RANGE="192.168.1.0/24" \
  -e NETBOX_HOST="https://netbox.example.com" \
  -e NETBOX_TOKEN="your_netbox_token" \
  -e DEPRECATION_THRESHOLD="24h" \
  -e DNS_SERVER="192.168.100.30:53" \
  -e SYN_SCAN="true" \
  tranceh2/netbox-go-discovery
```

#### Running with Network Capabilities

Since the application uses Nmap (which requires raw socket access), run the container with additional capabilities (without running as root):

```bash
docker run -d \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e TARGET_RANGE="192.168.1.0/24" \
  -e NETBOX_HOST="https://netbox.example.com" \
  -e NETBOX_TOKEN="your_netbox_token" \
  -e DEPRECATION_THRESHOLD="24h" \
  -e DNS_SERVER="192.168.100.30:53" \
  -e SYN_SCAN="true" \
  tranceh2/netbox-go-discovery
```

> **Note:** The `--cap-add=NET_RAW` and `--cap-add=NET_ADMIN` flags allow the container to open raw sockets, enabling the SYN scan functionality required by Nmap.

## Kubernetes Deployment

Below is an example Kubernetes deployment manifest. This example assumes you store sensitive configuration values in a Kubernetes Secret named `netbox-go-discovery-secrets`.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbox-go-discovery
spec:
  replicas: 1
  selector:
    matchLabels:
      app: netbox-go-discovery
  template:
    metadata:
      labels:
        app: netbox-go-discovery
    spec:
      containers:
        - name: netbox-go-discovery
          image: tranceh2/netbox-go-discovery:latest
          ports:
            - containerPort: 8080
          env:
            - name: TARGET_RANGE
              value: "192.168.1.0/24"
            - name: NETBOX_HOST
              valueFrom:
                secretKeyRef:
                  name: netbox-go-discovery-secrets
                  key: NETBOX_HOST
            - name: NETBOX_TOKEN
              valueFrom:
                secretKeyRef:
                  name: netbox-go-discovery-secrets
                  key: NETBOX_TOKEN
            - name: CONCURRENCY_LIMIT
              value: "50"
            - name: VERBOSE
              value: "true"
            - name: DETAILED_IP_LOGS
              value: "false"
            - name: LOG_FORMAT
              value: "text"
            - name: HEALTH_PORT
              value: "8080"
            - name: CRON_SCHEDULE
              value: "0 0 * * *"
            - name: DEPRECATION_THRESHOLD
              value: "24h"
            - name: DNS_SERVER
              value: "192.168.100.30:53"
            - name: SYN_SCAN
              value: "true"
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            capabilities:
              add: ["NET_RAW", "NET_ADMIN"]
---
apiVersion: v1
kind: Service
metadata:
  name: netbox-go-discovery
spec:
  selector:
    app: netbox-go-discovery
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 8080
```

### Instructions for Kubernetes

1. **Create the Secret:**

   ```bash
   kubectl create secret generic netbox-go-discovery-secrets \
     --from-literal=NETBOX_HOST="https://netbox.example.com" \
     --from-literal=NETBOX_TOKEN="your_netbox_token"
   ```

2. **Deploy:**

   Save the manifest in a file (e.g., `deployment.yaml`) and apply it:

   ```bash
   kubectl apply -f deployment.yaml
   ```

## Monitoring

- **Prometheus Metrics:**
  The application exposes Prometheus metrics on the `/metrics` endpoint.
- **Health Check:**
  A health check endpoint is available at `/healthz`.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for improvements or bug fixes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
