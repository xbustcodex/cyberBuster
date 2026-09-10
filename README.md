# Security Master

**Cross-platform hardened analyst toolchain + fleet dashboard.**
Not an OS. A reproducible tooling + policy layer that turns any Linux or Windows box
into a hardened analyst workstation with red / blue / analyst profiles available on demand.

```
  ██████  ▓█████  ▄████▄   ███▄ ▄███▓ ▄▄▄        ██████ ▄▄▄█████▓▓█████  ██▀███
▒██    ▒  ▓█   ▀ ▒██▀ ▀█  ▓██▒▀█▀ ██▒▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
░ ▓██▄    ▒███   ▒▓█    ▄ ▓██    ▓██░▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
  ▒   ██▒ ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██    ▒██ ░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄
▒██████▒▒ ░▒████▒▒ ▓███▀ ░▒██▒   ░██▒ ▓█   ▓██▒▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
```

> _CLI-first. Every dashboard action shows the underlying command._
> _No hidden GUI-only paths._

---

## Table of contents

- [What this is](#what-this-is)
- [Design decisions (locked)](#design-decisions-locked)
- [Architecture](#architecture)
- [Feature tour](#feature-tour)
- [Quick start](#quick-start)
- [Directory layout](#directory-layout)
- [API surface](#api-surface)
- [Tech stack](#tech-stack)
- [Non-goals (read this)](#non-goals-read-this)
- [Roadmap](#roadmap)
- [License](#license)

---

## What this is

Security Master is three things layered together:

1. **NixOS side (Phase 1):** A Nix flake with three `specialisation` blocks —
   `offense`, `defense`, `analyst` — reboot into any of them from the bootloader.
2. **Windows side (Phase 2):** A PowerShell DSC configuration set + Winget/Chocolatey
   manifest that mirrors the Linux profile as closely as Windows allows.
3. **Companion dashboard (Phase 4):** A React + FastAPI + MongoDB fleet manager
   that tracks profile state, tool versions, CVE alerts, and IOC enrichment
   across every enrolled workstation.

The dashboard is **fully functional today**. The Nix and PowerShell scaffolding
is production-quality reference material that plugs into a real host once you
run the bootstrap.

---

## Design decisions (locked)

- **Base for Linux:** NixOS. Reproducible, rollback-able, one config = one
  machine.
- **No custom kernel hardening.** Keeps offensive tools functional. Standard
  kernel with sane defaults only.
- **Multi-profile posture** — pick per host at bootloader (Linux) or via
  `Set-SMProfile` (Windows):
  - `offense` — full red-team toolkit, permissive network stack, MAC
    randomization, Tor / VPN chain ready
  - `defense` — DFIR + blue-team tooling, AppArmor permissive-log mode,
    immutable-ish rootfs
  - `analyst` — daily driver: research, reversing, OSINT, malware triage in VMs
- **Cross-platform:** Linux is first-class. Windows targets ~70% parity.
- **Public distribution:** signed releases, versioned flake outputs, CVE feed.

---

## Architecture

```
                                        ┌────────────────────────┐
                                        │   Dashboard (React)    │
                                        │  /fleet /cves /plugins │
                                        │  /automations /sigma   │
                                        └───────────┬────────────┘
                                                    │ https + JWT (httpOnly)
                                        ┌───────────▼────────────┐
                                        │  FastAPI  (backend)    │
                                        │  auth · fleet · cve    │
                                        │  plugins · ioc · sigma │
                                        │  scheduler · marketplc │
                                        └───┬────────────────┬───┘
                                            │ Motor          │ Fernet-at-rest
                                     ┌──────▼──────┐   ┌─────▼─────┐
                                     │  MongoDB    │   │  Secrets  │
                                     │  fleet, CVE │   │  encrypted│
                                     │  templates  │   └───────────┘
                                     └──────▲──────┘
                                            │ bearer (agent_token)
                    ┌────────────────┬──────┴───────┬────────────────┐
                    │                │              │                │
              ┌─────▼─────┐    ┌─────▼─────┐  ┌─────▼─────┐    ┌─────▼─────┐
              │  Linux    │    │  Windows  │  │  Linux    │    │  Windows  │
              │  NixOS    │    │  DSC      │  │  NixOS    │    │  DSC      │
              │  offense  │    │  defense  │  │  analyst  │    │  analyst  │
              │  (agent)  │    │  (agent)  │  │  (agent)  │    │  (agent)  │
              └───────────┘    └───────────┘  └───────────┘    └───────────┘
```

---

## Feature tour

### Fleet Overview
Dense terminal-style table of every enrolled workstation with profile badges
(red / blue / purple), status dots, per-row **profile switch** actions, and a
one-click **fleet-wide bulk IOC sweep** button.

### Workstation Detail
Left column: metadata, tools table (drift-diff toggle), audit timeline.
Right rail: **IOC enrichment panel** — VirusTotal reputation, Shodan open
ports / vulns, and a hash watchlist you can grow by pasting MD5 / SHA1 /
SHA256 or importing Sigma rules.

### CVE Alerts
NVD-shaped CVE table sorted by severity, filterable, with per-row remediation
commands and matched-host counts. `POST /api/cves/rescan` re-matches installed
tool versions and dispatches `cve.matched` to every subscribed plugin.

### Profile Distribution
Bars for profile mix, OS split (nixos-flake vs windows-dsc, honestly reporting
Windows parity ~72%), and CVE severity distribution.

### Signed Releases
Cosign-verified stream of versioned flake outputs and DSC bundles with a
release-manifest modal (commit sha, signer, channel, install command).

### Plugins (integration layer)
Ten built-in plugin types across four categories:

| Category | Plugins |
|---|---|
| Alerting | Slack · Discord · PagerDuty · Gotify |
| SIEM | Splunk HEC · Elasticsearch · MISP |
| Enrichment | VirusTotal · Shodan |
| Custom | Generic Webhook (HMAC-SHA256 signed) |

Each plugin:
- Auto-generates its config form from a schema (URL, text, select, bool,
  secret, event-subscription checkboxes)
- Encrypts secrets at rest with Fernet (key derived from `JWT_SECRET` via
  HKDF-SHA256)
- Masks secrets in every API response (`abcd••••••••wxyz`)
- Logs every dispatch in `plugin_executions` with HTTP status + latency +
  response snippet
- Fires on real events: `cve.matched`, `workstation.enrolled`,
  `workstation.profile_switched`, `manual.test`

### Sigma Rule Import
Paste one or more Sigma rules (multi-doc YAML supported). The parser:
- Sweeps the raw doc for MD5 / SHA1 / SHA256 hex literals (dialect-agnostic)
- Preserves rule titles / IDs / severity levels
- Applies extracted hashes to every online host (or the entire fleet) as
  watchlist entries tagged `sigma: <rule title>`

### Automations (background scheduler)
Three schedule-driven engines running on a single 60-second async tick:

- **Scheduled bulk sweeps** — nightly VT + Shodan enrichment of every online
  host without pressing a button.
- **Sigma repo sync** — point at any public GitHub Sigma repo (`SigmaHQ/sigma`
  works out of the box), pull `.yml` / `.yaml` files, extract hashes, apply.
- **Template marketplace** — every dashboard publishes an HMAC-SHA256 signed
  feed of `shared: true` templates at `/api/marketplace/feed`. Peer dashboards
  subscribe by URL + optional signing key. Subscribed templates land locally
  as read-only, verified entries.

### Command palette / CLI mirror
Every GUI action opens a slide-over drawer showing the equivalent shell
command in `bash` or `powershell` with copy-to-clipboard. Written into the
project as a core brand promise, not a nice-to-have.

---

## Quick start

### Dashboard (this repo)

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8001

# Frontend
cd frontend
yarn install
yarn start
```

Default admin (auto-seeded on first backend start):

```
email:    admin@secmaster.io
password: admin1234
```

The backend also seeds **12 workstations, 8 CVEs, 5 signed releases** so the
UI is meaningful on first login.

### Agent enrollment (any real Linux / Windows host)

```bash
# Linux
curl -sSL https://your-dashboard/api/agent/bootstrap.sh | \
  ENROLL_TOKEN="<one-time-token>" HOSTNAME="hydra-red-01" bash

# Windows (PowerShell)
iwr https://your-dashboard/api/agent/bootstrap.ps1 -UseB | iex
Invoke-SMEnroll -Token "<one-time-token>" -Hostname "chimera-blue-01"
```

Or run the built-in simulator without touching a real host:

```bash
python3 infrastructure/agent/agent.py --simulate 5 \
  --dashboard http://localhost:8001
```

### NixOS install (Phase 1)

```nix
{
  inputs.security-master.url = "github:xbustcodex/cyberBuster?dir=infrastructure/nix";

  outputs = { self, nixpkgs, security-master, ... }: {
    nixosConfigurations.my-analyst-box = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [ security-master.nixosModules.default ];
    };
  };
}
```

Then at boot, choose `offense`, `defense`, or `analyst` from the bootloader.

### Windows install (Phase 2)

```powershell
Import-Module .\infrastructure\windows\SecurityMaster.psm1
.\infrastructure\windows\profiles.dsc.ps1
Set-SMProfile analyst
```

---

## Directory layout

```
/app
├── backend/                # FastAPI service
│   ├── server.py           # all HTTP routes
│   ├── auth.py             # JWT + bcrypt + httpOnly cookies
│   ├── models.py           # pydantic schemas
│   ├── seed.py             # first-boot seed data
│   ├── plugins/
│   │   ├── catalog.py      # 10 built-in plugin types
│   │   ├── executor.py     # async dispatch + query handlers
│   │   └── crypto.py       # Fernet at-rest encryption
│   ├── sigma_parser.py     # Sigma YAML → hash extractor
│   ├── sigma_sync.py       # GitHub repo puller
│   ├── marketplace.py      # signed feed + subscription import
│   └── scheduler.py        # 60s background tick
│
├── frontend/               # React + Tailwind + shadcn/ui
│   └── src/
│       ├── pages/
│       │   ├── FleetOverview.jsx
│       │   ├── WorkstationDetail.jsx      # + IocPanel right rail
│       │   ├── CveAlerts.jsx
│       │   ├── ProfileDistribution.jsx
│       │   ├── SignedReleases.jsx
│       │   ├── Plugins.jsx                # catalog + templates + exec log
│       │   ├── SigmaImport.jsx
│       │   ├── Automations.jsx            # schedules + sigma + marketplace
│       │   ├── Enroll.jsx
│       │   └── Login.jsx
│       ├── components/
│       │   ├── Layout.jsx                 # sidebar + status bar + CLI drawer
│       │   ├── CliDrawer.jsx
│       │   └── IocPanel.jsx
│       ├── context/AuthContext.jsx
│       └── constants/testIds/             # data-testid registry
│
├── infrastructure/         # Phase 1-2 static artifacts
│   ├── nix/
│   │   ├── flake.nix
│   │   └── profiles/
│   │       ├── offense.nix
│   │       ├── defense.nix
│   │       └── analyst.nix
│   ├── windows/
│   │   ├── SecurityMaster.psm1
│   │   └── profiles.dsc.ps1
│   └── agent/
│       └── agent.py        # --enroll · --heartbeat · --simulate
│
├── memory/
│   ├── PRD.md              # product spec + backlog
│   └── test_credentials.md
│
└── README.md               # this file
```

---

## API surface

### Auth
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET  /api/auth/me`
- `POST /api/auth/refresh`

### Fleet
- `GET    /api/workstations` (filters: `profile`, `status`, `q`)
- `GET    /api/workstations/{id}`
- `POST   /api/workstations/{id}/switch-profile`
- `DELETE /api/workstations/{id}`

### Enrollment
- `POST /api/enroll/generate` (authed → one-time token)
- `POST /api/agent/enroll` (agent → exchanges token for bearer)
- `POST /api/agent/heartbeat` (agent bearer required)

### CVE / Stats / Audit / Releases
- `GET  /api/cves` (`severity` filter)
- `POST /api/cves/rescan`
- `GET  /api/releases`
- `GET  /api/stats/overview`
- `GET  /api/audit`

### Plugins & Templates
- `GET/POST /api/plugins`
- `PATCH/DELETE /api/plugins/{id}`
- `POST /api/plugins/{id}/test`
- `POST /api/plugins/{id}/query` (VirusTotal / Shodan)
- `GET  /api/plugins/{id}/executions`
- `GET  /api/plugins/catalog`
- `GET  /api/plugins/events`
- `POST /api/plugins/{id}/save-as-template`
- `POST /api/plugins/from-template/{tpl_id}`
- `GET  /api/plugin-templates`
- `PATCH/DELETE /api/plugin-templates/{tpl_id}`

### IOC
- `GET  /api/workstations/{id}/ioc`
- `POST /api/workstations/{id}/ioc/lookup`
- `POST/DELETE /api/workstations/{id}/ioc/hashes[/{hash}]`
- `POST /api/ioc/bulk-sweep`

### Sigma
- `POST /api/sigma/preview`
- `POST /api/sigma/import`

### Automations
- `GET/POST/PATCH/DELETE /api/schedules[/...]`
- `POST /api/schedules/{id}/run-now`
- `GET/POST/PATCH/DELETE /api/sigma-sources[/...]`
- `POST /api/sigma-sources/{id}/sync-now`
- `GET /api/marketplace/info`
- `GET /api/marketplace/feed` (**public, HMAC-signed**)
- `POST /api/marketplace/rotate-key`
- `GET/POST/PATCH/DELETE /api/marketplace/subscriptions[/...]`
- `POST /api/marketplace/subscriptions/{id}/sync-now`

---

## Tech stack

| Layer | Choice |
|---|---|
| Linux config | Nix flakes · home-manager · NixOS 24.11 |
| Windows config | PowerShell 7 · DSC v3 · Winget · Chocolatey fallback |
| Backend | Python 3.11 · FastAPI · Motor (async Mongo) · httpx · PyJWT · bcrypt · cryptography (Fernet + HKDF) |
| Frontend | React 18 · Tailwind · shadcn/ui · react-router · lucide-react · sonner (toasts) |
| Storage | MongoDB |
| Signing | HMAC-SHA256 for marketplace feed · cosign for release bundles (Phase 3) |
| Build | GitHub Actions for reproducible flake builds (Phase 3) |

Palette: Tokyo Night. Fonts: JetBrains Mono for data, IBM Plex Sans for chrome.

---

## Non-goals (read this)

- **"Best of red + blue + black team in one always-on posture" is not real.**
  The profile engine is the honest answer. Drifting toward a single always-on
  posture makes this project mediocre-Kali. Don't.
- **Windows parity will always lag Linux.** Accept ~70% coverage. Anything
  else is a fantasy.
- **No kernel hardening = do not market this as "hardened against nation-state
  actors."** It's hardened against opportunistic threats and misconfig, not
  against a targeted 0-day. Be honest in the docs.
- **The dashboard is not a SIEM.** It's a fleet manager with an integration
  layer. Ship events to your real SIEM via the Splunk-HEC or Elasticsearch
  plugin.

---

## Roadmap

- **P0 · Phase 3:** GitHub Actions build pipeline + cosign signing job
- **P1 · Phase 5:** Live NVD CVE feed sync (currently seeded)
- **P1:** Reproducibility verification (`nix build --check` on cron)
- **P1:** Container-based offense sandbox as a fourth profile mode
- **P1:** MFA / WebAuthn for dashboard operators
- **P2:** Fleet-health heat-map on Profile Distribution
- **P2:** Public docs site (mkdocs)
- **P2:** mTLS for agent → dashboard (currently bearer token)

---

## License

MIT. See `LICENSE` for details.

Contributions welcome. Read `memory/PRD.md` for backlog priorities and the
project's non-goals policy before opening a PR.
