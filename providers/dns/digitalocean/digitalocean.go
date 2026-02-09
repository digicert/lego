// Package digitalocean implements a DNS provider for solving the DNS-01 challenge using digitalocean DNS.
package digitalocean

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/digicert/lego/v4/challenge"
	"github.com/digicert/lego/v4/challenge/dns01"
	"github.com/digicert/lego/v4/platform/config/env"
	"github.com/digicert/lego/v4/providers/dns/digitalocean/internal"
	"github.com/digicert/lego/v4/providers/dns/internal/clientdebug"
)

// Environment variables names.
const (
	envNamespace = "DO_"

	EnvAuthToken = envNamespace + "AUTH_TOKEN"
	EnvAPIUrl    = envNamespace + "API_URL"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
	EnvHTTPTimeout        = envNamespace + "HTTP_TIMEOUT"
)

var _ challenge.ProviderTimeout = (*DNSProvider)(nil)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	BaseURL            string
	AuthToken          string
	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	HTTPClient         *http.Client
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		BaseURL:            env.GetOrDefaultString(EnvAPIUrl, internal.DefaultBaseURL),
		TTL:                env.GetOrDefaultInt(EnvTTL, 30),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, 5*time.Second),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond(EnvHTTPTimeout, 30*time.Second),
		},
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client

	recordIDs   map[string]int
	recordIDsMu sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for Digital
// Ocean. Credentials must be passed in the environment variable:
// DO_AUTH_TOKEN.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvAuthToken)
	if err != nil {
		return nil, fmt.Errorf("digitalocean: %w", err)
	}

	config := NewDefaultConfig()
	config.AuthToken = values[EnvAuthToken]

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for Digital Ocean.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("digitalocean: the configuration of the DNS provider is nil")
	}

	if config.AuthToken == "" {
		return nil, errors.New("digitalocean: credentials missing")
	}

	client := internal.NewClient(
		clientdebug.Wrap(
			internal.OAuthStaticAccessToken(config.HTTPClient, config.AuthToken),
		),
	)

	if config.BaseURL != "" {
		var err error

		client.BaseURL, err = url.Parse(config.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("digitalocean: %w", err)
		}
	}

	return &DNSProvider{
		config:    config,
		client:    client,
		recordIDs: make(map[string]int),
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("digitalocean: could not find zone for domain %q: %w", domain, err)
	}

	record := internal.Record{Type: "TXT", Name: info.EffectiveFQDN, Data: info.Value, TTL: d.config.TTL}

	respData, err := d.client.AddTxtRecord(context.Background(), authZone, record)
	if err != nil {
		return fmt.Errorf("digitalocean: %w", err)
	}

	d.recordIDsMu.Lock()
	d.recordIDs[token] = respData.DomainRecord.ID
	d.recordIDsMu.Unlock()

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("digitalocean: could not find zone for domain %q: %w", domain, err)
	}
	fmt.Printf("digitalocean: cleaning up TXT records for domain %s, zone %s\n", domain, authZone)
	// First try from our record ID map
	d.recordIDsMu.Lock()
	recordID, ok := d.recordIDs[token]
	d.recordIDsMu.Unlock()

	if ok {
		fmt.Printf("digitalocean: found record ID %d in map for token %s\n", recordID, token)
		err = d.client.RemoveTxtRecord(context.Background(), authZone, recordID)
		if err != nil {
			return fmt.Errorf("digitalocean: failed to remove TXT record with ID %d: %w", recordID, err)
		}

		fmt.Printf("digitalocean: successfully deleted TXT record with ID %d\n", recordID)

		// Delete record ID from map
		d.recordIDsMu.Lock()
		delete(d.recordIDs, token)
		d.recordIDsMu.Unlock()
	}

	records, err := d.client.ListRecords(context.Background(), authZone)
	if err != nil {
		return fmt.Errorf("digitalocean: failed to list records for zone %s: %w", authZone, err)
	}

	for _, record := range records {
		if record.Type == "TXT" && record.Name == info.EffectiveFQDN {
			fmt.Printf("digitalocean: found matching TXT record with ID %d for %s\n", record.ID, info.EffectiveFQDN)

			err = d.client.RemoveTxtRecord(context.Background(), authZone, record.ID)
			if err != nil {
				return fmt.Errorf("digitalocean: failed to remove TXT record with ID %d: %w", record.ID, err)
			}

			fmt.Printf("digitalocean: successfully deleted TXT record with ID %d\n", record.ID)
		}
	}
	return nil
}
