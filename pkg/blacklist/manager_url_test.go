package blacklist

import (
	"net"
	"net/http"
	"net/http/httptest"
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

	m, err := NewManager("", urls, 0)
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
