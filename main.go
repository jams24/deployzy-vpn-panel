// deployzy-vpn-panel is a self-hostable, white-label VPN reseller panel. It is
// deployed as a Deployzy template (single Go binary, one small container) and
// drives the TunnelTweak Deploy API under the hood using a per-panel API key.
//
// The panel owner logs into the admin section (credentials from env) to install
// and manage their own VPS servers and VPN accounts, and to configure an
// optional public page where their own free users self-create SSH/V2Ray access.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html
var tmplFS embed.FS

type App struct {
	tut       *TutBot
	store     *Store
	tmpl      *template.Template
	adminUser string
	adminPass string
	secret    []byte
	panelName string

	// naive per-IP daily counter for the public free page
	ipMu   sync.Mutex
	ipDay  string
	ipHits map[string]int
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	adminUser := env("ADMIN_USERNAME", "admin")
	adminPass := os.Getenv("ADMIN_PASSWORD")
	apiKey := os.Getenv("TUNNELTWEAK_API_KEY")
	baseURL := env("TUNNELTWEAK_BASE_URL", "https://tunneltweak.deployzy.com")
	port := env("PORT", "8080")
	dataDir := env("DATA_DIR", "/data")
	panelName := env("PANEL_NAME", "VPN Panel")

	if adminPass == "" {
		log.Fatal("ADMIN_PASSWORD is required")
	}
	if apiKey == "" {
		log.Fatal("TUNNELTWEAK_API_KEY is required (auto-injected by Deployzy; or paste your own)")
	}

	// Session secret: explicit env, else derived from the admin password so
	// sessions survive restarts without extra config.
	secretSrc := env("SESSION_SECRET", adminPass+"|"+adminUser)
	sum := sha256.Sum256([]byte(secretSrc))

	store, err := NewStore(dataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"title": strings.Title,
	}).ParseFS(tmplFS, "templates/*.html"))

	app := &App{
		tut:       NewTutBot(baseURL, apiKey),
		store:     store,
		tmpl:      tmpl,
		adminUser: adminUser,
		adminPass: adminPass,
		secret:    sum[:],
		panelName: panelName,
		ipHits:    map[string]int{},
	}

	// Confirm the API key works, but don't block startup on a transient blip.
	if uid, err := app.tut.Ping(context.Background()); err != nil {
		log.Printf("warning: TunnelTweak ping failed: %v", err)
	} else {
		log.Printf("connected to TunnelTweak as account #%d", uid)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	// Public
	mux.HandleFunc("GET /", app.handleRoot)
	mux.HandleFunc("POST /free", app.handleFreeCreate)

	// Auth
	mux.HandleFunc("GET /login", app.handleLoginForm)
	mux.HandleFunc("POST /login", app.handleLogin)
	mux.HandleFunc("POST /logout", app.handleLogout)

	// Admin (guarded)
	mux.HandleFunc("GET /admin", app.guard(app.handleAdmin))
	mux.HandleFunc("POST /admin/servers", app.guard(app.handleInstallServer))
	mux.HandleFunc("GET /admin/servers/{id}", app.guard(app.handleServerDetail))
	mux.HandleFunc("POST /admin/servers/{id}/delete", app.guard(app.handleDeleteServer))
	mux.HandleFunc("POST /admin/servers/{id}/users", app.guard(app.handleCreateUser))
	mux.HandleFunc("POST /admin/users/{id}/delete", app.guard(app.handleDeleteUser))
	mux.HandleFunc("POST /admin/users/{id}/renew", app.guard(app.handleRenewUser))
	mux.HandleFunc("GET /admin/jobs/{id}", app.guard(app.handleJobStatus))
	mux.HandleFunc("GET /admin/public", app.guard(app.handlePublicConfigForm))
	mux.HandleFunc("POST /admin/public", app.guard(app.handlePublicConfigSave))

	log.Printf("%s listening on :%s", panelName, port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// ── Sessions (signed cookie, stdlib only) ──────────────────────────────────

const cookieName = "dzy_vpn_sess"

func (a *App) sign(payload string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *App) setSession(w http.ResponseWriter, r *http.Request) {
	exp := time.Now().Add(12 * time.Hour).Unix()
	payload := fmt.Sprintf("%s.%d", a.adminUser, exp)
	val := payload + "." + a.sign(payload)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: val, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		Expires: time.Unix(exp, 0),
	})
}

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 3)
	if len(parts) != 3 {
		return false
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(a.sign(payload)), []byte(parts[2])) {
		return false
	}
	exp, _ := strconv.ParseInt(parts[1], 10, 64)
	return time.Now().Unix() < exp
}

func (a *App) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

// ── Rendering ──────────────────────────────────────────────────────────────

func (a *App) render(w http.ResponseWriter, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["PanelName"] = a.panelName
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "render error", 500)
	}
}

func jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ── Auth handlers ──────────────────────────────────────────────────────────

func (a *App) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if a.authed(r) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	a.render(w, "login.html", nil)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	u := r.FormValue("username")
	p := r.FormValue("password")
	okU := hmac.Equal([]byte(u), []byte(a.adminUser))
	okP := hmac.Equal([]byte(p), []byte(a.adminPass))
	if !okU || !okP {
		a.render(w, "login.html", map[string]any{"Error": "Invalid username or password."})
		return
	}
	a.setSession(w, r)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ── Admin handlers ─────────────────────────────────────────────────────────

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	servers, err := a.tut.ListServers(r.Context())
	data := map[string]any{"Servers": servers, "Public": a.store.Public()}
	if err != nil {
		data["Error"] = err.Error()
	}
	a.render(w, "admin.html", data)
}

func (a *App) handleInstallServer(w http.ResponseWriter, r *http.Request) {
	profile, _ := strconv.Atoi(r.FormValue("install_profile"))
	if profile == 0 {
		profile = 1
	}
	sshPort, _ := strconv.Atoi(r.FormValue("ssh_port"))
	req := CreateServerReq{
		Label:          strings.TrimSpace(r.FormValue("label")),
		Host:           strings.TrimSpace(r.FormValue("host")),
		SSHPort:        sshPort,
		RootPassword:   r.FormValue("root_password"),
		SSHKey:         r.FormValue("ssh_key"),
		InstallProfile: profile,
		DNSTTDomain:    strings.TrimSpace(r.FormValue("dnstt_domain")),
	}
	resp, err := a.tut.CreateServer(r.Context(), req)
	if err != nil {
		servers, _ := a.tut.ListServers(r.Context())
		a.render(w, "admin.html", map[string]any{"Servers": servers, "Public": a.store.Public(), "Error": err.Error()})
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/servers/%d?job=%d", resp.ServerID, resp.JobID), http.StatusSeeOther)
}

func (a *App) handleServerDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	srv, err := a.tut.GetServer(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	users, _ := a.tut.ListUsers(r.Context(), id)
	cfg, _ := a.tut.ServerConfig(r.Context(), id)
	data := map[string]any{
		"Server": srv, "Users": users, "Config": cfg,
		"JobID": r.URL.Query().Get("job"),
	}
	a.render(w, "server.html", data)
}

func (a *App) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	a.tut.DeleteServer(r.Context(), id)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (a *App) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	days, _ := strconv.Atoi(r.FormValue("days"))
	maxLogins, _ := strconv.Atoi(r.FormValue("max_logins"))
	_, err := a.tut.CreateUser(r.Context(), id, CreateUserReq{
		Username:  strings.TrimSpace(r.FormValue("username")),
		Password:  r.FormValue("password"),
		Days:      days,
		MaxLogins: maxLogins,
	})
	dest := fmt.Sprintf("/admin/servers/%d", id)
	if err != nil {
		dest += "?err=" + urlEncode(err.Error())
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (a *App) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	uid, _ := strconv.Atoi(r.PathValue("id"))
	a.tut.DeleteUser(r.Context(), uid)
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

func (a *App) handleRenewUser(w http.ResponseWriter, r *http.Request) {
	uid, _ := strconv.Atoi(r.PathValue("id"))
	days, _ := strconv.Atoi(r.FormValue("days"))
	if days == 0 {
		days = 30
	}
	a.tut.RenewUser(r.Context(), uid, days)
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

func (a *App) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	job, err := a.tut.GetJob(r.Context(), id)
	if err != nil {
		jsonResp(w, 200, map[string]any{"status": "unknown", "message": err.Error()})
		return
	}
	jsonResp(w, 200, job)
}

func (a *App) handlePublicConfigForm(w http.ResponseWriter, r *http.Request) {
	servers, _ := a.tut.ListServers(r.Context())
	a.render(w, "public_config.html", map[string]any{"Cfg": a.store.Public(), "Servers": servers})
}

func (a *App) handlePublicConfigSave(w http.ResponseWriter, r *http.Request) {
	sid, _ := strconv.Atoi(r.FormValue("server_id"))
	days, _ := strconv.Atoi(r.FormValue("days"))
	ml, _ := strconv.Atoi(r.FormValue("max_logins"))
	pid, _ := strconv.Atoi(r.FormValue("per_ip_daily"))
	cfg := PublicConfig{
		Enabled:    r.FormValue("enabled") == "on",
		ServerID:   sid,
		Days:       max1(days, 1),
		MaxLogins:  max1(ml, 1),
		PerIPDaily: max1(pid, 1),
	}
	a.store.SetPublic(cfg)
	http.Redirect(w, r, "/admin/public", http.StatusSeeOther)
}

// ── Public (free) handlers ─────────────────────────────────────────────────

func (a *App) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cfg := a.store.Public()
	if !cfg.Enabled || cfg.ServerID == 0 {
		// No public offering — send visitors to the admin login.
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	a.render(w, "public.html", map[string]any{"Cfg": cfg})
}

func (a *App) handleFreeCreate(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Public()
	if !cfg.Enabled || cfg.ServerID == 0 {
		http.Error(w, "Free accounts are not available.", 403)
		return
	}
	if !a.ipAllow(clientIP(r), cfg.PerIPDaily) {
		a.render(w, "public.html", map[string]any{"Cfg": cfg, "Error": "Daily limit reached from your network. Try again tomorrow."})
		return
	}
	user, err := a.tut.CreateUser(r.Context(), cfg.ServerID, CreateUserReq{
		Username:  strings.TrimSpace(r.FormValue("username")),
		Password:  r.FormValue("password"),
		Days:      cfg.Days,
		MaxLogins: cfg.MaxLogins,
	})
	if err != nil {
		a.render(w, "public.html", map[string]any{"Cfg": cfg, "Error": err.Error()})
		return
	}
	a.render(w, "public.html", map[string]any{"Cfg": cfg, "Created": user})
}

// ── helpers ────────────────────────────────────────────────────────────────

func (a *App) ipAllow(ip string, limit int) bool {
	a.ipMu.Lock()
	defer a.ipMu.Unlock()
	today := time.Now().UTC().Format("2006-01-02")
	if a.ipDay != today {
		a.ipDay = today
		a.ipHits = map[string]int{}
	}
	if a.ipHits[ip] >= limit {
		return false
	}
	a.ipHits[ip]++
	return true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func urlEncode(s string) string {
	return strings.NewReplacer(" ", "%20", "&", "%26", "?", "%3F", "#", "%23").Replace(s)
}

func max1(v, floor int) int {
	if v < floor {
		return floor
	}
	return v
}
