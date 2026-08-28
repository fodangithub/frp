package blacklist

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsBlacklisted_JSONArray(t *testing.T) {
	jsonData := `[
		{"network": "10.0.0.1"},
		{"network": "192.168.1.0/24"},
		{"network": "fd00::1"},
		{"network": "fd00:abcd::/32"}
	]`

	tmpFile := filepath.Join(os.TempDir(), "blacklist_test_array.json")
	if err := os.WriteFile(tmpFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(tmpFile)

	m, err := NewManager(tmpFile, nil, nil, 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Stop()

	tests := []struct {
		addr     string
		expected bool
	}{
		{"10.0.0.1:8080", true},
		{"10.0.0.2:8080", false},
		{"192.168.1.100:8080", true},
		{"192.168.2.100:8080", false},
		{"[fd00::1]:8080", true},
		{"[fd00::2]:8080", false},
		{"[fd00:abcd::1234]:8080", true},
		{"[fd00:abce::1]:8080", false},
		{"1.2.3.4:8080", false},
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

func TestIsBlacklisted_NDJSON(t *testing.T) {
	jsonData := `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"10.0.0.1","sblid":"SBL000001","rir":"arin"}
{"cidr":"192.168.1.0/24","sblid":"SBL000002","rir":"ripencc"}
{"type":"metadata","timestamp":1234567890,"size":3,"records":2}
`

	tmpFile := filepath.Join(os.TempDir(), "blacklist_test_ndjson.json")
	if err := os.WriteFile(tmpFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(tmpFile)

	m, err := NewManager(tmpFile, nil, nil, 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Stop()

	tests := []struct {
		addr     string
		expected bool
	}{
		{"1.10.16.1:8080", true},
		{"1.10.32.1:8080", false},
		{"10.0.0.1:8080", true},
		{"10.0.0.2:8080", false},
		{"192.168.1.50:8080", true},
		{"192.168.2.50:8080", false},
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

func TestEmptyBlacklist(t *testing.T) {
	m, err := NewManager("", nil, nil, 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Stop()

	addr, _ := net.ResolveTCPAddr("tcp", "1.2.3.4:8080")
	if m.IsBlacklisted(addr) {
		t.Error("empty blacklist should not block any IP")
	}
}

func TestMissingFile(t *testing.T) {
	m, err := NewManager("/nonexistent/blacklist.json", nil, nil, 0)
	if err != nil {
		t.Fatalf("NewManager should not fail on missing file: %v", err)
	}
	defer m.Stop()

	addr, _ := net.ResolveTCPAddr("tcp", "1.2.3.4:8080")
	if m.IsBlacklisted(addr) {
		t.Error("missing file should result in empty blacklist")
	}
}

func TestRefreshInterval(t *testing.T) {
	jsonData := `[{"cidr": "10.0.0.0/8"}]`
	tmpFile := filepath.Join(os.TempDir(), "blacklist_refresh_test.json")
	if err := os.WriteFile(tmpFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(tmpFile)

	m, err := NewManager(tmpFile, nil, nil, 1*time.Second)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Stop()
}

func TestAdditionalFiles_MergedAcrossFiles(t *testing.T) {
	file1 := filepath.Join(os.TempDir(), "blacklist_additional_1.json")
	file2 := filepath.Join(os.TempDir(), "blacklist_additional_2.json")
	if err := os.WriteFile(file1, []byte(`[{"network": "203.0.113.0/24"}, {"network": "10.50.0.1"}]`), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(file1)
	if err := os.WriteFile(file2, []byte(`{"cidr":"198.51.100.0/24"}`+"\n"+`{"cidr":"2001:db8:1::/48"}`), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(file2)

	m, err := NewManager("", []string{file1, file2}, nil, 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Stop()

	tests := []struct {
		addr     string
		expected bool
	}{
		{"203.0.113.9:8080", true},
		{"10.50.0.1:8080", true},
		{"198.51.100.7:8080", true},
		{"[2001:db8:1::1]:8080", true},
		{"203.0.114.9:8080", false},
		{"10.50.0.2:8080", false},
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

func TestAdditionalFiles_MissingOrMalformedFileSkipped(t *testing.T) {
	valid := filepath.Join(os.TempDir(), "blacklist_additional_valid.json")
	malformed := filepath.Join(os.TempDir(), "blacklist_additional_malformed.json")
	if err := os.WriteFile(valid, []byte(`[{"network": "203.0.113.7"}]`), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(valid)
	if err := os.WriteFile(malformed, []byte(`[{"network": `), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(malformed)

	m, err := NewManager("", []string{"/nonexistent/extra.json", malformed, valid}, nil, 0)
	if err != nil {
		t.Fatalf("NewManager should not fail on missing/malformed additional files: %v", err)
	}
	defer m.Stop()

	blocked, _ := net.ResolveTCPAddr("tcp", "203.0.113.7:8080")
	if !m.IsBlacklisted(blocked) {
		t.Error("entries from the valid additional file should be blacklisted")
	}
}

func TestMetadataSkipped(t *testing.T) {
	jsonData := `{"type":"metadata","timestamp":1234567890,"size":0,"records":0}`

	tmpFile := filepath.Join(os.TempDir(), "blacklist_metadata_test.json")
	if err := os.WriteFile(tmpFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	defer os.Remove(tmpFile)

	m, err := NewManager(tmpFile, nil, nil, 0)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer m.Stop()

	addr, _ := net.ResolveTCPAddr("tcp", "1.2.3.4:8080")
	if m.IsBlacklisted(addr) {
		t.Error("metadata-only file should result in empty blacklist")
	}
}
