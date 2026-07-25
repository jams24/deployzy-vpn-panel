package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// PublicConfig is the owner-configurable public free-SSH offering. Everything
// else (servers, accounts) lives in TunnelTweak; only this small policy is local.
type PublicConfig struct {
	Enabled   bool `json:"enabled"`    // is the public free page open?
	ServerID  int  `json:"server_id"`  // which server free accounts are created on
	Days      int  `json:"days"`       // account lifetime
	MaxLogins int  `json:"max_logins"` // simultaneous logins per account
	// Simple abuse guard: max accounts a single IP can create per day.
	PerIPDaily int `json:"per_ip_daily"`
}

func defaultPublicConfig() PublicConfig {
	return PublicConfig{Enabled: false, ServerID: 0, Days: 7, MaxLogins: 1, PerIPDaily: 2}
}

// Store persists PublicConfig to a JSON file on the data volume.
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  PublicConfig
}

func NewStore(dir string) (*Store, error) {
	if dir == "" {
		dir = "/data"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// Fall back to cwd if the volume isn't writable — panel still runs.
		dir = "."
	}
	s := &Store{path: filepath.Join(dir, "public_config.json"), cfg: defaultPublicConfig()}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.cfg)
	}
	return s, nil
}

func (s *Store) Public() PublicConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Store) SetPublic(c PublicConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(s.path, b, 0o644)
}
