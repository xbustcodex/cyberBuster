# Security Master — Companion Dashboard PRD

## Original problem statement
Cross-platform hardened analyst toolchain: Nix flake (Linux) + PowerShell DSC
(Windows) profile engine (offense / defense / analyst) with a companion
web dashboard that tracks fleet workstations, profile state, tool versions,
and CVE alerts. CLI-first, dense, Tokyo-Night terminal UX.

## User personas
- Single security analyst on a hardened workstation
- Team lead viewing multi-workstation fleet health
- Red / blue / DFIR operator switching posture on demand

## Core requirements (locked)
- Multi-profile posture engine (no always-on kitchen sink)
- No kernel hardening (offensive tools must keep working)
- Windows parity ~70% target (documented honestly)
- Pinned release cadence with cosign signatures
- CLI-first: every GUI action has a shell equivalent

---

## Implemented

### 2026-02-08 · iteration 1 — dashboard + scaffolding
- FastAPI + MongoDB backend, React + Tailwind + shadcn frontend, JWT (httpOnly cookie + Bearer)
- Fleet overview, workstation detail, CVE alerts, profile distribution, releases, enrollment, CLI drawer
- `POST /api/agent/enroll`, `POST /api/agent/heartbeat`
- `/infrastructure`: nix flake + profiles, Windows psm1 + DSC, agent.py

### iteration 2 — integrations
- Plugin engine (webhook, Slack, Discord, Splunk HEC, Elastic, PagerDuty, MISP, Gotify, VirusTotal, Shodan…) with Fernet-encrypted secrets, templates, marketplace feed
- IOC panel + bulk IOC sweep, Sigma rule import + GitHub repo sync, scheduled automations
- README.md

### 2026-09-11 · iteration 3 — "make it real" (user: "turn it into a real app not fake")
- **Demo data labelled + purgeable**: all seed docs carry `demo: true`; yellow DEMO tags in fleet/CVE/release views; top banner with one-click purge (`DELETE /api/demo-data`); never re-seeds after purge. User chose to keep demo data rather than wipe.
- **Real enrollment**: `/api/agent/bootstrap.sh` + `bootstrap.ps1` served by the backend (install agent.py, enroll, systemd unit / NixOS transient unit / Windows Scheduled Task). `agent.py`, `SecurityMaster.psm1`, `sec-master` CLI also served.
- **Real agent** (`infrastructure/agent/agent.py` 1.0.0): `--simulate` removed; detects ~40 tools via `--version`; sha256 of flake.lock / DSC module; local IP; applies `desired_profile` via `nixos-rebuild switch --specialisation` / `Set-SMProfile` / `SM_SWITCH_CMD`; reports apply errors.
- **Real profile switch**: sets `desired_profile`, host = drift until agent applies and reports; audit trail for request/applied/failed; demo hosts still flip instantly.
- **Real status engine** (`fleet_status.py`): offline after `OFFLINE_AFTER_SECONDS` (300) without heartbeat, drift on desired≠reported; 30 s loop.
- **Real CVE feed** (`nvd.py`): NVD 2.0 `virtualMatchString=cpe:2.3:a:*:<tool>` per fleet tool, CPE version-range matching against installed versions, per-host match counts, NVD links; `POST /api/cves/sync` (background) + `GET /api/cves/sync-status`; alerts capped at 15 new critical/high hits per sync; built-in daily schedule. NVD_API_KEY configured.
- **Real releases** (`releases_sync.py`): GitHub Releases API for `GITHUB_RELEASES_REPO=xbustcodex/cyberBuster`; signed = sigstore/cosign asset attached; assets + verify command in modal; empty-state with instructions; built-in daily schedule.
- **Release pipeline**: `.github/workflows/release.yml` — v* tag → tar infrastructure → cosign keyless sign-blob → GitHub release with .tar.gz/.sha256/.bundle.
- **Operator CLI** `infrastructure/cli/sec-master` (login, fleet list/show/switch/forget, cve list/sync/status/rescan, releases list/sync, enroll generate, ioc sweep, demo status/purge).
- `nixosModules.agent` (`infrastructure/nix/modules/agent.nix`) for a persistent agent service on NixOS.
- Heartbeat now records X-Forwarded-For public IP, `local_ip`, `os_release`, tool-inventory change audit events, "back online" events.

## Environment (backend/.env)
`NVD_API_URL`, `NVD_API_KEY`, `GITHUB_RELEASES_REPO`, `OFFLINE_AFTER_SECONDS`, optional `GITHUB_TOKEN`.

## Known honest limitations
- Releases are "signed" when a cosign/sigstore asset is attached; server-side `cosign verify-blob` is not run (cosign not installed in the backend container).
- CPE product matching is by name — vendor collisions possible (e.g. Ruby `curl` gem).
- Demo hosts are excluded from the status engine (they never go offline).
- xbustcodex/cyberBuster currently has 0 GitHub releases → empty state until the first `v*` tag is pushed.

## Backlog
- **P1:** Server-side cosign verification of release bundles
- **P1:** Fleet-health heat-map (IOC hits / CVE hits per day)
- **P1:** Container-based offense sandbox as fourth profile mode
- **P1:** MFA / WebAuthn for dashboard operators
- **P2:** CVE auto-route rules per plugin (e.g. PagerDuty only for critical on 3+ hosts)
- **P2:** Public docs site (mkdocs)
- **P2:** mTLS for agent → dashboard
- **P2:** Refactor `server.py` (~1500 lines) into APIRouters

## Test credentials
See `/app/memory/test_credentials.md` — `admin@secmaster.io` / `admin1234`.
