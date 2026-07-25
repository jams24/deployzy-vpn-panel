# Deployzy VPN Panel

A self-hostable, white-label **SSH / V2Ray reseller panel**. Deploy it from the
Deployzy templates gallery, log into the admin section, install your own VPS
servers, manage VPN accounts, and (optionally) open a public page where your
own free users self-create accounts.

It's a single Go binary with an embedded UI and **no database** — all server and
account state lives in the [TunnelTweak](https://tunneltweak.deployzy.com) Deploy
API, which this panel drives using a per-panel API key.

## Environment variables

| Var | Required | Default | Purpose |
|-----|----------|---------|---------|
| `ADMIN_USERNAME` | – | `admin` | Admin login username |
| `ADMIN_PASSWORD` | ✅ | – | Admin login password |
| `TUNNELTWEAK_API_KEY` | ✅ | – | Panel's TunnelTweak key (auto-injected by Deployzy, or bring your own) |
| `TUNNELTWEAK_BASE_URL` | – | `https://tunneltweak.deployzy.com` | TunnelTweak API base |
| `PANEL_NAME` | – | `VPN Panel` | Branding shown in the UI |
| `PORT` | – | `8080` | HTTP port |
| `DATA_DIR` | – | `/data` | Where the public-page policy is stored |
| `SESSION_SECRET` | – | derived | Overrides the cookie-signing secret |

## Run locally

```bash
ADMIN_PASSWORD=changeme TUNNELTWEAK_API_KEY=ttk_... go run .
# open http://localhost:8080/login
```

## Docker

```bash
docker build -t deployzy-vpn-panel .
docker run -p 8080:8080 -e ADMIN_PASSWORD=changeme -e TUNNELTWEAK_API_KEY=ttk_... deployzy-vpn-panel
```

## What the admin can do

- **Install servers** — point at a fresh root Ubuntu/Debian VPS; TunnelTweak
  installs the VPN stack over SSH (profiles: Full / WS+Stunnel / DNSTT / mgmt).
- **Manage accounts** — create, renew, and delete SSH/V2Ray accounts per server.
- **Public free page** — enable a homepage where anyone can self-create a free
  account on a chosen server, with your own duration / login / per-IP limits.
