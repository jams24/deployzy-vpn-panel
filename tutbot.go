package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TutBot is a client for the TunnelTweak Deploy API, scoped to this panel's key.
type TutBot struct {
	BaseURL string
	APIKey  string
	http    *http.Client
}

func NewTutBot(baseURL, apiKey string) *TutBot {
	return &TutBot{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

type apiErr struct {
	Status  int
	Code    string
	Message string
}

func (e *apiErr) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("tutbot error (status %d)", e.Status)
}

func (c *TutBot) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &apiErr{Status: 502, Code: "unreachable", Message: "Could not reach the VPN backend: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		var env struct {
			Error struct {
				Code, Message string
			} `json:"error"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Error.Message != "" {
			return &apiErr{Status: resp.StatusCode, Code: env.Error.Code, Message: env.Error.Message}
		}
		return &apiErr{Status: resp.StatusCode, Code: "http_error", Message: strings.TrimSpace(string(raw))}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// ── Types ──────────────────────────────────────────────────────────────────

type Server struct {
	ID              int            `json:"id"`
	Label           string         `json:"label"`
	Host            string         `json:"host"`
	SSHPort         int            `json:"ssh_port"`
	IP              string         `json:"ip"`
	InstallProfile  int            `json:"install_profile"`
	ProvisionStatus string         `json:"provision_status"`
	HealthStatus    string         `json:"health_status"`
	Services        map[string]any `json:"services"`
	Ports           map[string]any `json:"ports"`
	Domain          string         `json:"domain"`
	CDNDomain       string         `json:"cdn_domain"`
	DNSTT           *DNSTTInfo     `json:"dnstt"`
	V2Ray          *V2RayInfo     `json:"v2ray"`
	CreatedAt       string         `json:"created_at"`
}

type DNSTTInfo struct {
	Domain     string `json:"domain"`
	Pubkey     string `json:"pubkey"`
	Nameserver string `json:"nameserver"`
}

type V2RayInfo struct {
	Protocol    string `json:"protocol"`
	UUID        string `json:"uuid"`
	Port        int    `json:"port"`
	CDNPort     int    `json:"cdn_port"`
	Security    string `json:"security"`
	SNI         string `json:"sni"`
	PublicKey   string `json:"public_key"`
	ShortID     string `json:"short_id"`
	Fingerprint string `json:"fingerprint"`
}

// Connection is the rich, client-agnostic config block the API returns on
// account create (with password) and read (without).
type Connection struct {
	Host  string          `json:"host"`
	SSH   *SSHConn        `json:"ssh"`
	V2Ray *V2RayConn      `json:"v2ray"`
	DNSTT *DNSTTInfo      `json:"dnstt"`
	Payload *PayloadConn  `json:"payload"`
}

type SSHConn struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	SSLPort  int    `json:"ssl_port"`
	WSPort   int    `json:"ws_port"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
}

type V2RayConn struct {
	Protocol    string    `json:"protocol"`
	UUID        string    `json:"uuid"`
	Port        int       `json:"port"`
	CDNPort     int       `json:"cdn_port"`
	Security    string    `json:"security"`
	Network     string    `json:"network"`
	SNI         string    `json:"sni"`
	PublicKey   string    `json:"public_key"`
	ShortID     string    `json:"short_id"`
	Fingerprint string    `json:"fingerprint"`
	URI         string    `json:"uri"`
	CDN         *V2RayCDN `json:"cdn"`
}

type V2RayCDN struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
	Security string `json:"security"`
	WSHost   string `json:"ws_host"`
	WSPath   string `json:"ws_path"`
	SNI      string `json:"sni"`
	URI      string `json:"uri"`
}

type PayloadConn struct {
	Host    string `json:"host"`
	Request string `json:"request"`
}

type Job struct {
	ID       int    `json:"id"`
	ServerID int    `json:"server_id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Error    string `json:"error"`
}

type TunnelUser struct {
	ID          int         `json:"id"`
	ServerID    int         `json:"server_id"`
	Username    string      `json:"username"`
	Password    string      `json:"password,omitempty"`
	ConnectCode string      `json:"connect_code,omitempty"`
	Status      string      `json:"status"`
	ExpiresAt   string      `json:"expires_at"`
	MaxLogins   int         `json:"max_logins"`
	HasV2Ray    bool        `json:"has_v2ray"`
	Connection  *Connection `json:"connection,omitempty"`
}

// ── Auth ───────────────────────────────────────────────────────────────────

func (c *TutBot) Ping(ctx context.Context) (int, error) {
	var out struct {
		OK     bool `json:"ok"`
		UserID int  `json:"user_id"`
	}
	err := c.do(ctx, "GET", "/api/v1", nil, &out)
	return out.UserID, err
}

// ── Servers ────────────────────────────────────────────────────────────────

type CreateServerReq struct {
	Label          string `json:"label"`
	Host           string `json:"host"`
	SSHPort        int    `json:"ssh_port,omitempty"`
	RootPassword   string `json:"root_password,omitempty"`
	SSHKey         string `json:"ssh_key,omitempty"`
	InstallProfile int    `json:"install_profile,omitempty"`
	DNSTTDomain    string `json:"dnstt_domain,omitempty"`
}

type CreateServerResp struct {
	ServerID int    `json:"server_id"`
	JobID    int    `json:"job_id"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

func (c *TutBot) CreateServer(ctx context.Context, req CreateServerReq) (*CreateServerResp, error) {
	var out CreateServerResp
	err := c.do(ctx, "POST", "/api/v1/servers", req, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *TutBot) ListServers(ctx context.Context) ([]Server, error) {
	var out struct {
		Servers []Server `json:"servers"`
	}
	err := c.do(ctx, "GET", "/api/v1/servers", nil, &out)
	return out.Servers, err
}

func (c *TutBot) GetServer(ctx context.Context, id int) (*Server, error) {
	var out Server
	err := c.do(ctx, "GET", fmt.Sprintf("/api/v1/servers/%d", id), nil, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *TutBot) DeleteServer(ctx context.Context, id int) error {
	return c.do(ctx, "DELETE", fmt.Sprintf("/api/v1/servers/%d", id), nil, nil)
}

func (c *TutBot) GetJob(ctx context.Context, id int) (*Job, error) {
	var out Job
	err := c.do(ctx, "GET", fmt.Sprintf("/api/v1/jobs/%d", id), nil, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Tunnel users ───────────────────────────────────────────────────────────

type CreateUserReq struct {
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Days      int    `json:"days,omitempty"`
	MaxLogins int    `json:"max_logins,omitempty"`
}

func (c *TutBot) CreateUser(ctx context.Context, serverID int, req CreateUserReq) (*TunnelUser, error) {
	var out TunnelUser
	err := c.do(ctx, "POST", fmt.Sprintf("/api/v1/servers/%d/users", serverID), req, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *TutBot) ListUsers(ctx context.Context, serverID int) ([]TunnelUser, error) {
	var out struct {
		Users []TunnelUser `json:"users"`
	}
	err := c.do(ctx, "GET", fmt.Sprintf("/api/v1/servers/%d/users", serverID), nil, &out)
	return out.Users, err
}

func (c *TutBot) GetUser(ctx context.Context, uid int) (*TunnelUser, error) {
	var out TunnelUser
	err := c.do(ctx, "GET", fmt.Sprintf("/api/v1/users/%d", uid), nil, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *TutBot) RenewUser(ctx context.Context, uid, days int) error {
	return c.do(ctx, "POST", fmt.Sprintf("/api/v1/users/%d/renew", uid), map[string]int{"days": days}, nil)
}

func (c *TutBot) SetUserLimit(ctx context.Context, uid, maxLogins int) error {
	return c.do(ctx, "POST", fmt.Sprintf("/api/v1/users/%d/limit", uid), map[string]int{"max_logins": maxLogins}, nil)
}

func (c *TutBot) DeleteUser(ctx context.Context, uid int) error {
	return c.do(ctx, "DELETE", fmt.Sprintf("/api/v1/users/%d", uid), nil, nil)
}

// RestartServer restarts the VPN services on a server.
func (c *TutBot) RestartServer(ctx context.Context, id int) error {
	return c.do(ctx, "POST", fmt.Sprintf("/api/v1/servers/%d/restart", id), nil, nil)
}

type ServerConfig struct {
	ServerID    int    `json:"server_id"`
	ConnectCode string `json:"connect_code"`
	ConfigURL   string `json:"config_url"`
}

func (c *TutBot) ServerConfig(ctx context.Context, serverID int) (*ServerConfig, error) {
	var out ServerConfig
	err := c.do(ctx, "GET", fmt.Sprintf("/api/v1/servers/%d/config", serverID), nil, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
