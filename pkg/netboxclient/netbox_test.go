package netboxclient_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	netbox "github.com/netbox-community/go-netbox/v4"
	"github.com/stretchr/testify/assert"

	"github.com/tranceh2/netbox-go-discovery/pkg/netboxclient"
)

// fakeGetIPResponse simula la respuesta de NetBox para la consulta de IPs.
func fakeGetIPResponse(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"count":    1,
		"next":     nil,
		"previous": nil,
		"results": []map[string]interface{}{
			{
				"id":      123,
				"url":     "http://fake/api/ipam/ip-addresses/123/",
				"display": "192.168.50.1/32",
				"address": "192.168.50.1/32",
				"family": map[string]interface{}{
					"value": 4,
					"label": "IPv4",
				},
				"nat_outside": []interface{}{}, // Campo requerido, se envía vacío
				"custom_fields": map[string]interface{}{
					"scantime": "2025-02-13T18:30:06-03:00",
				},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func TestGetNetboxIPs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(fakeGetIPResponse))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	assert.NoError(t, err)

	cfg := netbox.NewConfiguration()
	cfg.Host = u.Host
	cfg.Scheme = u.Scheme
	apiClient := netbox.NewAPIClient(cfg)

	ips, err := netboxclient.GetNetboxIPs(apiClient, "192.168.50.0/24")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(ips))
	if len(ips) > 0 {
		assert.Equal(t, "192.168.50.1/32", ips[0].Address)
	}
}

func fakeCreateIPResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	response := map[string]interface{}{
		"id":      456,
		"url":     "http://fake/api/ipam/ip-addresses/456/",
		"display": "192.168.50.2/32", // Campo requerido
		"address": "192.168.50.2/32",
		"family": map[string]interface{}{
			"value": 4,
			"label": "IPv4",
		},
		"nat_outside": []interface{}{},
	}
	json.NewEncoder(w).Encode(response)
}

func TestCreateNetboxIP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(fakeCreateIPResponse))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	assert.NoError(t, err)

	cfgNetbox := netbox.NewConfiguration()
	cfgNetbox.Host = u.Host
	cfgNetbox.Scheme = u.Scheme
	apiClient := netbox.NewAPIClient(cfgNetbox)

	err = netboxclient.CreateNetboxIP(apiClient, "192.168.50.2", "testdns", "active", map[string]interface{}{
		"scantime": time.Now().Format(time.RFC3339),
	})
	assert.NoError(t, err)
}

func fakeUpdateIPResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]interface{}{
		"id":      789,
		"url":     "http://fake/api/ipam/ip-addresses/789/",
		"display": "192.168.50.3/32", // Campo requerido
		"address": "192.168.50.3/32",
		"family": map[string]interface{}{
			"value": 4,
			"label": "IPv4",
		},
		"nat_outside": []interface{}{},
	}
	json.NewEncoder(w).Encode(response)
}

func TestUpdateNetboxIP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(fakeUpdateIPResponse))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	assert.NoError(t, err)

	cfgNetbox := netbox.NewConfiguration()
	cfgNetbox.Host = u.Host
	cfgNetbox.Scheme = u.Scheme
	apiClient := netbox.NewAPIClient(cfgNetbox)

	err = netboxclient.UpdateNetboxIP(apiClient, "192.168.50.3", "testdns-update", "active", map[string]interface{}{
		"scantime": time.Now().Format(time.RFC3339),
	}, 789)
	assert.NoError(t, err)
}

func fakeMarkDeprecatedResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]interface{}{
		"id":      1011,
		"url":     "http://fake/api/ipam/ip-addresses/1011/",
		"display": "192.168.50.4/32", // Campo requerido
		"address": "192.168.50.4/32",
		"family": map[string]interface{}{
			"value": 4,
			"label": "IPv4",
		},
		"nat_outside": []interface{}{},
	}
	json.NewEncoder(w).Encode(response)
}

func TestMarkNetboxIPDeprecated(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(fakeMarkDeprecatedResponse))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	assert.NoError(t, err)

	cfgNetbox := netbox.NewConfiguration()
	cfgNetbox.Host = u.Host
	cfgNetbox.Scheme = u.Scheme
	apiClient := netbox.NewAPIClient(cfgNetbox)

	err = netboxclient.MarkNetboxIPDeprecated(apiClient, 1011)
	assert.NoError(t, err)
}

func TestParseScanTime(t *testing.T) {
	nbip := netbox.IPAddress{
		CustomFields: map[string]interface{}{
			"scantime": "2025-02-13T18:30:06-03:00",
		},
	}
	parsedTime, err := netboxclient.ParseScanTime(&nbip)
	assert.NoError(t, err)
	assert.False(t, parsedTime.IsZero(), "Expected a valid time, got zero time")
}
