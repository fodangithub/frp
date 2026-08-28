package blacklist

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchFromURLs_SpamhausFormat(t *testing.T) {
	spamhausV4 := `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"10.99.0.0/16","sblid":"SBL999999","rir":"arin"}
{"cidr":"192.0.2.0/24","sblid":"SBL000001","rir":"ripencc"}
{"type":"metadata","timestamp":1786063442,"size":5752,"records":91,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`

	spamhausV6 := `{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}
{"cidr":"2001:db8::/32","sblid":"SBL999998","rir":"ripencc"}
{"type":"metadata","timestamp":1786063442,"size":1000,"records":50}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/drop_v4.json":
			w.Write([]byte(spamhausV4))
		case "/drop_v6.json":
			w.Write([]byte(spamhausV6))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	urls := []string{
		srv.URL + "/drop_v4.json",
		srv.URL + "/drop_v6.json",
	}

	m, err := NewManager("", nil, urls, 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Stop()

	if err := m.fetchFromURLs(); err != nil {
		t.Fatalf("fetchFromURLs: %v", err)
	}

	tests := []struct {
		addr     string
		expected bool
	}{
		{"1.10.20.1:8080", true},
		{"1.10.32.1:8080", false},
		{"10.99.1.1:8080", true},
		{"10.98.1.1:8080", false},
		{"192.0.2.100:8080", true},
		{"192.0.3.100:8080", false},
		{"[2001:678:254::1]:8080", true},
		{"[2001:678:255::1]:8080", false},
		{"[2001:db8::1]:8080", true},
		{"[2001:db9::1]:8080", false},
	}

	for _, tt := range tests {
		addr, err := net.ResolveTCPAddr("tcp", tt.addr)
		if err != nil {
			t.Fatalf("resolve %s: %v", tt.addr, err)
		}
		got := m.IsBlacklisted(addr)
		if got != tt.expected {
			t.Errorf("IsBlacklisted(%s) = %v, want %v", tt.addr, got, tt.expected)
		}
	}
}

func TestAdditionalFiles_SurviveURLRefresh(t *testing.T) {
	// Static entries in additional files must keep being enforced after a
	// URL fetch replaces the dynamic set, and the additional files must not
	// be overwritten.
	additionalContent := []byte(`[{"network": "203.0.113.0/24"}, {"network": "10.50.0.1"}]`)
	additionalFile := filepath.Join(os.TempDir(), "blacklist_additional_survive.json")
	if err := os.WriteFile(additionalFile, additionalContent, 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(additionalFile)

	cacheFile := filepath.Join(os.TempDir(), "blacklist_cache_survive.json")
	defer os.Remove(cacheFile)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}`))
	}))
	defer srv.Close()

	m, err := NewManager(cacheFile, []string{additionalFile}, []string{srv.URL}, 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Stop()

	// Re-fetch to simulate a refresh cycle.
	if err := m.fetchFromURLs(); err != nil {
		t.Fatalf("fetchFromURLs: %v", err)
	}

	tests := []struct {
		addr     string
		expected bool
	}{
		// static entries still enforced after refresh
		{"203.0.113.9:8080", true},
		{"10.50.0.1:8080", true},
		// dynamic entries from the URL
		{"1.10.20.1:8080", true},
		// neither
		{"8.8.8.8:8080", false},
	}

	for _, tt := range tests {
		addr, err := net.ResolveTCPAddr("tcp", tt.addr)
		if err != nil {
			t.Fatalf("resolve %s: %v", tt.addr, err)
		}
		got := m.IsBlacklisted(addr)
		if got != tt.expected {
			t.Errorf("IsBlacklisted(%s) = %v, want %v", tt.addr, got, tt.expected)
		}
	}

	// The cache file is rewritten with fetched content, but the additional
	// file must be untouched.
	cacheContent, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatalf("read cache file: %v", err)
	}
	if !bytes.Contains(cacheContent, []byte("1.10.16.0/20")) {
		t.Errorf("cache file should contain fetched content, got %q", cacheContent)
	}

	got, err := os.ReadFile(additionalFile)
	if err != nil {
		t.Fatalf("read additional file: %v", err)
	}
	if !bytes.Equal(got, additionalContent) {
		t.Errorf("additional file was modified: got %q, want %q", got, additionalContent)
	}
}
