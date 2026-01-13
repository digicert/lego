package micetro

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

type Client struct {
	baseURL    string
	username   string
	password   string

	sessionKey string
	mu         sync.Mutex

	httpClient *http.Client
}

func NewClient(cfg *Config) *Client {
	base := strings.TrimSuffix(cfg.Endpoint, "/")
	base = strings.TrimSuffix(base, "/v2")

	return &Client{
		baseURL: base,
		username: cfg.Username,
		password: cfg.Password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

//
// ---------- SESSION HANDLING ----------
//

func (c *Client) login() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// already logged in
	if c.sessionKey != "" {
		return nil
	}

	payload := map[string]string{
		"loginName": c.username,
		"password":  c.password,
	}

	body, _ := json.Marshal(payload)

	u, _ := url.Parse(c.baseURL)
	u.Path = path.Join(u.Path, "v2", "micetro", "sessions")

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("micetro: login failed: %s: %s", resp.Status, string(b))
	}

	var response struct {
		Result struct {
			Session string `json:"session"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	if response.Result.Session == "" {
		return fmt.Errorf("micetro: empty session key returned")
	}

	c.sessionKey = response.Result.Session
	return nil
}

//
// ---------- REQUEST WRAPPER ----------
//

func (c *Client) doRequest(method, urlStr string, body io.Reader) (*http.Response, error) {
	if err := c.login(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.sessionKey)

	return c.httpClient.Do(req)
}

//
// ---------- ZONE LISTING ----------
//

type zoneItem struct {
	Name string `json:"name"`
}

type zoneListResponse struct {
	Result struct {
		DNSZones []zoneItem `json:"dnsZones"`
	} `json:"result"`
}

func (c *Client) listZones() ([]string, error) {
	u, _ := url.Parse(c.baseURL)
	u.Path = path.Join(u.Path, "v2",  "dnsZones")
	resp, err := c.doRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("micetro: listZones failed: %s: %s", resp.Status, string(b))
	}

	var wrapper zoneListResponse
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, err
	}

	var zones []string
	for _, z := range wrapper.Result.DNSZones {
		zones = append(zones, strings.TrimSuffix(z.Name, "."))
	}

	return zones, nil
}

//
// ---------- DNS RECORD OPERATIONS ----------
//

func (c *Client) AddTXTRecord(zone, name, value string, ttl int) error {
	var fqdn string
	if strings.HasSuffix(name, ".") {
		fqdn = name
	} else {
		fqdn = name + "." + zone + "."
	}

	rec := map[string]interface{}{
		"name": fqdn,
		"type": "TXT",
		"data": value,
		"ttl":  ttl,
		"enabled": true,
	}

	recJSON, _ := json.Marshal(rec)

	u, _ := url.Parse(c.baseURL)
	u.Path = path.Join(u.Path, "v2", "dnsZones", zone, "dnsRecords")

	q := u.Query()
	q.Set("dnsRecord", string(recJSON))
	u.RawQuery = q.Encode()

	resp, err := c.doRequest(http.MethodPost, u.String(), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("micetro: AddTXTRecord failed: %s: %s", resp.Status, string(b))
	}

	return nil
}

func (c *Client) DeleteTXTRecord(zone, name, value string) error {
	var fqdn string
	if strings.HasSuffix(name, ".") {
		fqdn = name
	} else {
		fqdn = name + "." + zone + "."
	}

	encoded := url.PathEscape(fqdn)
	urlStr := fmt.Sprintf("%s/v2/dnsRecords/%s", c.baseURL, encoded)

	resp, err := c.doRequest(http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("micetro: DeleteTXTRecord failed: %s: %s", resp.Status, string(b))
	}

	return nil
}
