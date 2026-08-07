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
	mu       sync.RWMutex
	networks []*net.IPNet
	ips      map[string]struct{}

	filePath        string
	refreshURLs     []string
	refreshInterval time.Duration
	stopCh          chan struct{}
}

func NewManager(filePath string, refreshURLs []string, refreshInterval time.Duration) (*Manager, error) {
	m := &Manager{
		ips:             make(map[string]struct{}),
		filePath:        filePath,
		refreshURLs:     refreshURLs,
		refreshInterval: refreshInterval,
		stopCh:          make(chan struct{}),
	}

	if err := m.loadFromFile(); err != nil {
		return nil, err
	}

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

	if _, ok := m.ips[ip.String()]; ok {
		return true
	}

	for _, network := range m.networks {
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

	return m.parseAndApply(data)
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

	if err := m.parseAndApply(allLines); err != nil {
		return err
	}

	if m.filePath != "" {
		if err := os.WriteFile(m.filePath, allLines, 0644); err != nil {
			log.Warn("blacklist: save merged list to %s failed: %v", m.filePath, err)
		}
	}

	log.Info("blacklist: refreshed from %d URLs", len(m.refreshURLs))
	return nil
}

func (m *Manager) parseAndApply(data []byte) error {
	var entries []blacklistEntry

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return fmt.Errorf("blacklist: parse JSON array: %v", err)
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
			return fmt.Errorf("blacklist: read NDJSON: %v", err)
		}
	}

	newIPs := make(map[string]struct{})
	var newNetworks []*net.IPNet

	for _, entry := range entries {
		if entry.Type == "metadata" {
			continue
		}

		network := entry.getNetwork()
		if network == "" {
			continue
		}

		if _, ipNet, err := net.ParseCIDR(network); err == nil {
			newNetworks = append(newNetworks, ipNet)
			continue
		}

		if ip := net.ParseIP(network); ip != nil {
			newIPs[ip.String()] = struct{}{}
			continue
		}

		log.Warn("blacklist: invalid entry %q, skipping", network)
	}

	m.mu.Lock()
	m.ips = newIPs
	m.networks = newNetworks
	m.mu.Unlock()

	log.Info("blacklist: loaded %d IPs and %d CIDR ranges", len(newIPs), len(newNetworks))
	return nil
}
