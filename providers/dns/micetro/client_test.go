package micetro

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAddAndDeleteTXTRecord(t *testing.T) {
	mux := http.NewServeMux()

	// list zones
	mux.HandleFunc("/dnsZones", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"dnsZones":[{"ref":"dnsZones/1","name":"example.com.","displayName":"example.com."}],"totalResults":1}}`)
	})

	// accept POST to create record
	mux.HandleFunc("/dnsZones/example.com./dnsRecords", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"result":{}}`)
	})

	// accept DELETE
	mux.HandleFunc("/dnsRecords/_acme-challenge.www.example.com.", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := &Config{
		Endpoint: server.URL,
		APIKey:   "testkey",
		TTL:      60,
	}

	client := NewClient(cfg)

	// test add
	if err := client.AddTXTRecord("example.com.", "_acme-challenge.www", "dummy-value", 60); err != nil {
		t.Fatalf("AddTXTRecord failed: %v", err)
	}

	// test delete
	if err := client.DeleteTXTRecord("example.com.", "_acme-challenge.www", "dummy-value"); err != nil {
		t.Fatalf("DeleteTXTRecord failed: %v", err)
	}
}
