package blacklist

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
)

type Manager struct {
	mu sync.RWMutex

	// Static entries loaded from additionalFiles at startup. They are merged
	// into the blacklist once and are never replaced or overwritten.
	staticIPs      map[string]struct{}
	staticNetworks []*net.IPNet

	// Dynamic entries, atomically replaced on every successful URL fetch.
	dynIPs      map[string]struct{}
	dynNetworks []*net.IPNet

	filePath        string
	additionalFiles []string
	refreshURLs     []string
	refreshInterval time.Duration
	stopCh          chan struct{}
}

func NewManager(filePath string, additionalFiles []string, refreshURLs []string, refreshInterval time.Duration) (*Manager, error) {
	m := &Manager{
		staticIPs:       make(map[string]struct{}),
		dynIPs:          make(map[string]struct{}),
		filePath:        filePath,
		additionalFiles: additionalFiles,
		refreshURLs:     refreshURLs,
		refreshInterval: refreshInterval,
		stopCh:          make(chan struct{}),
	}

	if err := m.loadFromFile(); err != nil {
		return nil, err
	}

	m.loadAdditionalFiles()

	if len(m.refreshURLs) > 0 {
		if err := m.fetchFromURLs(); err != nil {
			log.Warn("blacklist: initial fetch from URLs failed: %v", err)
		}
	}

	if m.refreshInterval > 0 && len(m.refreshURLs) > 0 {
		go m.refreshLoop()
	}

	return m, nil
}

func (m *Manager) IsBlacklisted(addr net.Addr) bool {
	if addr == nil {
		return false
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.staticIPs[ip.String()]; ok {
		return true
	}
	if _, ok := m.dynIPs[ip.String()]; ok {
		return true
	}

	for _, network := range m.staticNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	for _, network := range m.dynNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (m *Manager) Stop() {
	close(m.stopCh)
}

func (m *Manager) refreshLoop() {
	ticker := time.NewTicker(m.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.fetchFromURLs(); err != nil {
				log.Warn("blacklist: refresh from URLs failed: %v", err)
			}
		case <-m.stopCh:
			return
		}
	}
}

type blacklistEntry struct {
	CIDR    string `json:"cidr"`
	Network string `json:"network"`
	Type    string `json:"type"`
}

func (e *blacklistEntry) getNetwork() string {
	if e.CIDR != "" {
		return e.CIDR
	}
	return e.Network
}

// loadFromFile loads the dynamic blacklist cache file (blacklist_file_path).
// It only seeds the dynamic set at startup; every successful URL fetch
// replaces it in memory and rewrites the file.
func (m *Manager) loadFromFile() error {
	if m.filePath == "" {
		return nil
	}

	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("blacklist: file %s not found, starting with empty list", m.filePath)
			return nil
		}
		return fmt.Errorf("blacklist: read file %s: %v", m.filePath, err)
	}

	ips, networks, err := parseEntries(data)
	if err != nil {
		return fmt.Errorf("blacklist: parse file %s: %v", m.filePath, err)
	}

	m.mu.Lock()
	m.dynIPs = ips
	m.dynNetworks = networks
	m.mu.Unlock()

	log.Info("blacklist: loaded %d IPs and %d CIDR ranges from %s", len(ips), len(networks), m.filePath)
	return nil
}

// loadAdditionalFiles loads static blacklist entries from all additional
// files. Entries are merged across files into the static set, which is never
// replaced or overwritten afterwards. A missing, unreadable or malformed
// file is logged and skipped so it cannot prevent frps from starting.
func (m *Manager) loadAdditionalFiles() {
	if len(m.additionalFiles) == 0 {
		return
	}

	staticIPs := make(map[string]struct{})
	var staticNetworks []*net.IPNet

	for _, path := range m.additionalFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				log.Warn("blacklist: additional file %s not found, skipping", path)
			} else {
				log.Warn("blacklist: read additional file %s failed: %v, skipping", path, err)
			}
			continue
		}

		ips, networks, err := parseEntries(data)
		if err != nil {
			log.Warn("blacklist: parse additional file %s failed: %v, skipping", path, err)
			continue
		}

		for ip := range ips {
			staticIPs[ip] = struct{}{}
		}
		staticNetworks = append(staticNetworks, networks...)
		log.Info("blacklist: loaded %d IPs and %d CIDR ranges from additional file %s", len(ips), len(networks), path)
	}

	m.mu.Lock()
	m.staticIPs = staticIPs
	m.staticNetworks = staticNetworks
	m.mu.Unlock()
}

func (m *Manager) fetchFromURLs() error {
	var allLines []byte

	for _, url := range m.refreshURLs {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			log.Warn("blacklist: fetch %s failed: %v", url, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Warn("blacklist: read response from %s failed: %v", url, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Warn("blacklist: fetch %s returned status %d", url, resp.StatusCode)
			continue
		}

		allLines = append(allLines, body...)
		if len(body) > 0 && body[len(body)-1] != '\n' {
			allLines = append(allLines, '\n')
		}
	}

	if len(allLines) == 0 {
		return nil
	}

	ips, networks, err := parseEntries(allLines)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.dynIPs = ips
	m.dynNetworks = networks
	m.mu.Unlock()

	if m.filePath != "" {
		if err := os.WriteFile(m.filePath, allLines, 0644); err != nil {
			log.Warn("blacklist: save merged list to %s failed: %v", m.filePath, err)
		}
	}

	log.Info("blacklist: refreshed %d IPs and %d CIDR ranges from %d URLs", len(ips), len(networks), len(m.refreshURLs))
	return nil
}

// parseEntries parses blacklist data in JSON array or NDJSON format and
// returns the contained individual IPs and CIDR networks.
func parseEntries(data []byte) (map[string]struct{}, []*net.IPNet, error) {
	var entries []blacklistEntry

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return nil, nil, fmt.Errorf("parse JSON array: %v", err)
		}
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var entry blacklistEntry
			if err := json.Unmarshal(line, &entry); err != nil {
				continue
			}
			entries = append(entries, entry)
		}
		if err := scanner.Err(); err != nil {
			return nil, nil, fmt.Errorf("read NDJSON: %v", err)
		}
	}

	ips := make(map[string]struct{})
	var networks []*net.IPNet

	for _, entry := range entries {
		if entry.Type == "metadata" {
			continue
		}

		network := entry.getNetwork()
		if network == "" {
			continue
		}

		if _, ipNet, err := net.ParseCIDR(network); err == nil {
			networks = append(networks, ipNet)
			continue
		}

		if ip := net.ParseIP(network); ip != nil {
			ips[ip.String()] = struct{}{}
			continue
		}

		log.Warn("blacklist: invalid entry %q, skipping", network)
	}

	return ips, networks, nil
}
