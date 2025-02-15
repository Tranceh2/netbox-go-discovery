# Netbox Go Discovery

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/tranceh2/netbox-go-discovery)](https://goreportcard.com/report/github.com/tranceh2/netbox-go-discovery)

Netbox Go Discovery is a tool that automatically discovers and manages IP addresses in your network and synchronizes them with your Netbox instance. It performs network scans, identifies active hosts, and updates Netbox accordingly, creating new IP entries, updating existing ones, and deprecating those that are no longer detected.

## Features

- **Automated Network Discovery:** Scans the network for active hosts using ping and SYN scans.
- **Netbox Synchronization:** Automatically creates, updates, and deprecates IP addresses in Netbox based on scan results.
- **Scheduled Scans:** Supports scheduled scans using cron expressions.
- **Concurrency Control:** Limits the number of concurrent scan operations to avoid overloading the network.
- **Detailed Logging:** Provides detailed logs of the scan process, including discovered hosts and Netbox updates.
- **Prometheus Metrics:** Exposes Prometheus metrics for monitoring scan performance and Netbox synchronization.
- **Health Check Endpoint:** Includes a health check endpoint for monitoring the application's status.

## Getting Started

### Prerequisites

- Go 1.23 or higher
- A running Netbox instance
- Network access to the target range
- A custom field named `scantime` of type "Date and Time" in Netbox. This field is used to store the timestamp of the last scan for each IP address. The application uses this field to determine if an IP address should be deprecated.

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

The application is configured using environment variables. The following variables are required:

- `TARGET_RANGE`: The IP range to scan (e.g., `192.168.1.0/24`).
- `NETBOX_HOST`: The URL of the Netbox instance (e.g., `https://netbox.example.com`).
- `NETBOX_TOKEN`: The authentication token for the Netbox API.

The following variables are optional:

- `CONCURRENCY_LIMIT`: The maximum number of concurrent scan operations (default: `50`).
- `VERBOSE`: Enable detailed logging output (default: `false`).
- `DETAILED_IP_LOGS`: Enable comprehensive IP scanning logs (default: `false`).
- `LOG_FORMAT`: The format of logs (`text` or `json`, default: `text`).
- `HEALTH_PORT`: The port for the health check endpoint (default: `8080`).
- `CRON_SCHEDULE`: The cron schedule for running scans (default: `0 0 * * *` - daily at midnight).

### Usage

1. Set the environment variables. For example:

   ```bash
   export TARGET_RANGE="192.168.1.0/24"
   export NETBOX_HOST="https://netbox.example.com"
   export NETBOX_TOKEN="your_netbox_token"
   ```

2. Run the application:

   ```bash
   ./netbox-go-discovery
   ```

### Running with Docker

1. Build the Docker image:

   ```bash
   docker build -t netbox-go-discovery .
   ```

2. Run the Docker container, passing the required environment variables:

   ```bash
   docker run -d \
     -e TARGET_RANGE="192.168.1.0/24" \
     -e NETBOX_HOST="https://netbox.example.com" \
     -e NETBOX_TOKEN="your_netbox_token" \
     netbox-go-discovery
   ```

## Monitoring

The application exposes Prometheus metrics on the `/metrics` endpoint. You can configure Prometheus to scrape these metrics to monitor the application's performance and Netbox synchronization.

The application also provides a health check endpoint on `/healthz`.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
