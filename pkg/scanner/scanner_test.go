package scanner_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tranceh2/netbox-go-discovery/pkg/scanner"
)

func TestIncIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	nextIP := scanner.IncIP(ip)
	expected := net.ParseIP("192.168.1.2")
	assert.True(t, expected.Equal(nextIP), "Expected %v, got %v", expected, nextIP)
}

func TestGenerateIPs(t *testing.T) {
	// Assuming GenerateIPs function returns IPs from a /24 excluding
	// network and broadcast addresses.
	cidr := "192.168.1.0/24"
	ips := scanner.GenerateIPs(cidr)
	// In a /24, 254 valid addresses are expected
	expected := 254
	assert.Equal(t, expected, len(ips), "Expected %d IPs, got %d", expected, len(ips))
}

func TestSubdivideTo24(t *testing.T) {
	// For a /16, subdividing into /24 should result in 256 subnets.
	_, ipNet, err := net.ParseCIDR("192.168.0.0/16")
	assert.NoError(t, err)
	subnets := scanner.SubdivideTo24(ipNet)
	expected := 256
	assert.Equal(t, expected, len(subnets), "Expected %d subnets, got %d", expected, len(subnets))
}
