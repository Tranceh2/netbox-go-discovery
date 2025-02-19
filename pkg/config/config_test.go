package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tranceh2/netbox-go-discovery/pkg/config"
)

func TestLoadConfig(t *testing.T) {
	// Establecer variables de entorno para la prueba.
	os.Setenv("TARGET_RANGE", "192.168.0.0/16")
	os.Setenv("NETBOX_HOST", "http://netbox.example.com")
	os.Setenv("NETBOX_TOKEN", "dummy_token")
	os.Setenv("VERBOSE", "true")
	os.Setenv("DETAILED_IP_LOGS", "false")
	os.Setenv("CONCURRENCY_LIMIT", "50")
	os.Setenv("HEALTH_PORT", "8080")
	os.Setenv("CRON_SCHEDULE", "0 0 * * *")
	os.Setenv("LOG_FORMAT", "text")

	cfg, err := config.LoadConfig()
	assert.NoError(t, err)
	assert.Equal(t, "192.168.0.0/16", cfg.TargetRange)
	assert.Equal(t, "http://netbox.example.com", cfg.NetboxHost)
	assert.Equal(t, "dummy_token", cfg.NetboxToken)
	assert.Equal(t, 50, cfg.ConcurrencyLimit)
	assert.Equal(t, "8080", cfg.HealthPort)
	assert.Equal(t, "0 0 * * *", cfg.CronSchedule)
	assert.Equal(t, "text", cfg.LogFormat)
}
