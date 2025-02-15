package netboxclient

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	netbox "github.com/netbox-community/go-netbox/v4"
	"github.com/rs/zerolog/log"
)

// GetNetboxIPs queries NetBox to retrieve IP addresses within the specified target range.
// It handles large IP ranges by subdividing them into /24 subnets for efficient querying.
// Returns a slice of IPAddress objects and any error encountered.
func GetNetboxIPs(apiClient *netbox.APIClient, targetRange string) ([]netbox.IPAddress, error) {
	_, ipNet, err := net.ParseCIDR(targetRange)
	if err != nil {
		return nil, fmt.Errorf("invalid range: %v", err)
	}
	ones, _ := ipNet.Mask.Size()
	var subnets []string
	if ones < 24 {
		subnets = SubdivideTo24(ipNet)
		log.Info().Msgf("Target range %s subdivided into %d /24 subnets for NetBox query.", targetRange, len(subnets))
	} else {
		subnets = []string{ipNet.String()}
	}

	var allIPs []netbox.IPAddress
	for _, subnet := range subnets {
		resp, httpResp, err := apiClient.IpamAPI.IpamIpAddressesList(context.Background()).
			Parent([]string{subnet}).
			Limit(300).
			Execute()
		if err != nil {
			log.Error().Msgf("Error querying NetBox for subnet %s: %v", subnet, err)
			continue
		}
		log.Debug().Msgf("Subnet %s: %d IPs obtained (HTTP: %v)", subnet, len(resp.Results), httpResp)
		allIPs = append(allIPs, resp.Results...)
	}
	return allIPs, nil
}

// SubdivideTo24 divides an IP block into /24 subnets.
// It takes an IPNet pointer and returns a slice of strings representing the /24 subnets.
// If the input is already a /24 or smaller, it returns the original network.
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

// CreateNetboxIP creates a new IP address entry in NetBox.
// It takes the host address, DNS name, status, and custom fields as parameters.
// Returns an error if the creation fails.
func CreateNetboxIP(apiClient *netbox.APIClient, hostAddress, dnsName, status string, customFields map[string]interface{}) error {
	netboxStatus := netbox.PatchedWritableIPAddressRequestStatus(status)
	description := "Automatically discovered via network scan"
	ipRequest := netbox.WritableIPAddressRequest{
		Address:      hostAddress + "/32",
		DnsName:      &dnsName,
		Status:       &netboxStatus,
		Description:  &description,
		CustomFields: customFields,
	}
	resp, httpResp, err := apiClient.IpamAPI.IpamIpAddressesCreate(context.Background()).
		WritableIPAddressRequest(ipRequest).Execute()
	if err != nil {
		log.Error().Msgf("Error creating IP in NetBox: %v", err)
		log.Debug().Msgf("HTTP response (create): %v", httpResp)
		return err
	}
	_ = resp
	return nil
}

// UpdateNetboxIP updates an existing IP address entry in NetBox.
// It takes the host address, DNS name, status, custom fields, and the IP's ID as parameters.
// Returns an error if the update fails.
func UpdateNetboxIP(apiClient *netbox.APIClient, hostAddress, dnsName, status string, customFields map[string]interface{}, id int32) error {
	netboxStatus := netbox.PatchedWritableIPAddressRequestStatus(status)
	ipAddress := netbox.PatchedWritableIPAddressRequest{
		Status:       &netboxStatus,
		DnsName:      &dnsName,
		CustomFields: customFields,
	}
	resp, httpResp, err := apiClient.IpamAPI.IpamIpAddressesPartialUpdate(context.Background(), id).
		PatchedWritableIPAddressRequest(ipAddress).Execute()
	if err != nil {
		log.Error().Msgf("Error updating IP in NetBox: %v", err)
		log.Debug().Msgf("HTTP response (update): %v", httpResp)
		return err
	}
	_ = resp
	return nil
}

// MarkNetboxIPDeprecated marks an IP address as "deprecated" in NetBox.
// It takes the IP's ID as a parameter and returns an error if the operation fails.
func MarkNetboxIPDeprecated(apiClient *netbox.APIClient, id int32) error {
	netboxStatus := netbox.PatchedWritableIPAddressRequestStatus("deprecated")
	ipAddress := netbox.PatchedWritableIPAddressRequest{
		Status: &netboxStatus,
	}
	resp, httpResp, err := apiClient.IpamAPI.IpamIpAddressesPartialUpdate(context.Background(), id).
		PatchedWritableIPAddressRequest(ipAddress).Execute()
	if err != nil {
		log.Error().Msgf("Error deprecating IP in NetBox: %v", err)
		log.Debug().Msgf("HTTP response (deprecated): %v", httpResp)
		return err
	}
	_ = resp
	return nil
}

// ParseScanTime parses the "scantime" custom field from a NetBox IP address.
// It returns the parsed time and any error encountered during parsing.
// The scantime field is expected to be in RFC3339 format.
func ParseScanTime(nbip *netbox.IPAddress) (time.Time, error) {
	if nbip.CustomFields == nil {
		return time.Time{}, fmt.Errorf("no custom fields present")
	}
	value, ok := nbip.CustomFields["scantime"]
	if !ok {
		return time.Time{}, fmt.Errorf("field 'scantime' not defined")
	}
	strVal, ok := value.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("field 'scantime' is not a string")
	}
	return time.Parse(time.RFC3339, strVal)
}
