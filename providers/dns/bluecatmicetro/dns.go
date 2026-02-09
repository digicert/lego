package bluecatmicetro

import (
	"fmt"
	"time"

	"github.com/digicert/lego/v4/challenge/dns01"
	"github.com/digicert/lego/v4/platform/config/env"
)

const (
	envNamespace = "BLUECAT_MICETRO_"

	envEndpoint = envNamespace + "ENDPOINT" // e.g., https://micetro.example/mmws/api/v2
	envUsername = envNamespace + "USERNAME"
	envPassword = envNamespace + "PASSWORD"
	envTTL      = envNamespace + "TTL"
)

type Config struct {
	Endpoint string
	APIKey   string
	Username string
	Password string
	TTL      int
}

func NewDefaultConfig() *Config {
	return &Config{
		Endpoint: env.GetOrDefaultString(envEndpoint, ""),
		Username: env.GetOrDefaultString(envUsername, ""),
		Password: env.GetOrDefaultString(envPassword, ""),
		TTL:      env.GetOrDefaultInt(envTTL, 10),
	}
}

type DNSProvider struct {
	cfg    *Config
	client *Client
}

func NewDNSProvider() (*DNSProvider, error) {
	cfg := NewDefaultConfig()
	return NewDNSProviderConfig(cfg)
}

func NewDNSProviderConfig(cfg *Config) (*DNSProvider, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("bluecatmicetro: %s must be set", envEndpoint)
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("bluecatmicetro: provide %s/%s", envUsername, envPassword)
	}

	client := NewClient(cfg)

	return &DNSProvider{
		cfg:    cfg,
		client: client,
	}, nil
}

func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zoneName, relative := FindBestZoneForFQDN(d.client, info.EffectiveFQDN)
	if zoneName == "" {
		return fmt.Errorf("bluecatmicetro: %w (%s)", ErrZoneNotFound, domain)
	}

	return d.client.AddTXTRecord(zoneName, relative, info.Value, d.cfg.TTL)
}

func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zoneName, relative := FindBestZoneForFQDN(d.client, info.EffectiveFQDN)
	if zoneName == "" {
		return fmt.Errorf("bluecatmicetro: %w (%s)", ErrZoneNotFound, domain)
	}

	return d.client.DeleteTXTRecord(zoneName, relative)
}

func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	// Conservative polling settings; adjust if your Micetro deployment is slower/faster.
	return 120 * time.Second, 10 * time.Second
}
