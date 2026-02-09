package bluecatmicetro

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginSuccess(t *testing.T) {
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/micetro/sessions" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result":{"session":"mock-session-key"}}`))
			return
		}
		t.Fatalf("Unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	client := NewClient(&Config{
		Endpoint: server.URL,
		Username: "user",
		Password: "pass",
	})

	if err := client.login(); err != nil {
		t.Fatalf("expected login success, got %v", err)
	}

	if client.sessionKey != "mock-session-key" {
		t.Fatalf("expected session key to be set")
	}
}

func TestAddTXTRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/dnsZones/zone1/dnsRecords") && r.Method == http.MethodPost {
			rec := r.URL.Query().Get("dnsRecord")
			if !strings.Contains(rec, "TXT") {
				t.Fatalf("expected TXT record in query, got %s", rec)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/v2/micetro/sessions" {
			w.Write([]byte(`{"result":{"session":"mock-session"}}`))
			return
		}
		t.Fatalf("Unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	client := NewClient(&Config{
		Endpoint: server.URL,
		Username: "user",
		Password: "pass",
	})

	err := client.AddTXTRecord("zone1", "test", "token", 60)
	if err != nil {
		t.Fatalf("expected AddTXTRecord success, got %v", err)
	}
}

func TestDeleteTXTRecord(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/dnsRecords/test.zone1." && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/v2/micetro/sessions" {
			w.Write([]byte(`{"result":{"session":"mock-session"}}`))
			return
		}
		t.Fatalf("Unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	client := NewClient(&Config{
		Endpoint: server.URL,
		Username: "user",
		Password: "pass",
	})

	err := client.DeleteTXTRecord("zone1", "test")
	if err != nil {
		t.Fatalf("expected DeleteTXTRecord success, got %v", err)
	}
}

func TestListZones(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/dnsZones" && r.Method == http.MethodGet {
			w.Write([]byte(`{"result":{"dnsZones":[{"name":"zone1."},{"name":"zone2."}]}}`))
			return
		}
		if r.URL.Path == "/v2/micetro/sessions" {
			w.Write([]byte(`{"result":{"session":"mock-session"}}`))
			return
		}
		t.Fatalf("Unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	client := NewClient(&Config{
		Endpoint: server.URL,
		Username: "user",
		Password: "pass",
	})

	zones, err := client.listZones()
	if err != nil {
		t.Fatalf("expected ListZones success, got %v", err)
	}

	if len(zones) != 2 || zones[0] != "zone1" || zones[1] != "zone2" {
		t.Fatalf("unexpected zones returned: %v", zones)
	}
}
