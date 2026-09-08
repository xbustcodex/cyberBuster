# Security Master — Companion Dashboard PRD

## Original problem statement
Cross-platform hardened analyst toolchain: Nix flake (Linux) + PowerShell DSC
(Windows) profile engine (offense / defense / analyst) with a companion
web dashboard that tracks fleet workstations, profile state, tool versions,
and CVE alerts.

## Delivered scope (2026-02-08, iteration 1)

### Companion Dashboard (Phase 4) — production-ready
- FastAPI + MongoDB backend, React + Tailwind + shadcn frontend
- JWT auth via httpOnly cookies + Bearer fallback (bcrypt hashing)
- Fleet overview: dense table with profile badges, status dots, per-row profile switch
- Workstation detail: metadata banner, tools table, audit timeline
- CVE alerts: severity-filtered table with remediation CLI commands
- Profile distribution: bars for profile / OS / status mix
- Signed releases: cosign-verified stream with release manifest modal
- Enrollment: one-time token generator with bash + powershell one-liners
- Command palette: CLI mirror drawer — every UI action shows equivalent shell command
- Live top status bar (fleet count, online/drift/offline) refreshing every 20s

### Agent flow (Phase 4 companion) — real, not mocked
- `POST /api/agent/enroll` (token → agent bearer)
- `POST /api/agent/heartbeat` (Bearer auth) updates last_heartbeat, profile, tools

### Infrastructure scaffolding (Phase 1–2 static artifacts)
Located at `/app/infrastructure/`:
- `nix/flake.nix` + three profile specialisations (offense / defense / analyst)
- `windows/SecurityMaster.psm1` (Set-SMProfile, Invoke-SMEnroll, Update-SMBundle)
- `windows/profiles.dsc.ps1` (BitLocker check, default-deny firewall, Sysmon, WEF)
- `agent/agent.py` — cross-platform reporting daemon with `--simulate N` mode

## User personas
- Single security analyst on a hardened workstation
- Team lead viewing multi-workstation fleet health
- Red / blue / DFIR operator switching posture on demand

## Core requirements (locked)
- Multi-profile posture engine (no always-on kitchen sink)
- No kernel hardening (offensive tools must keep working)
- Windows parity ~70% target (documented honestly)
- Pinned quarterly release cadence with cosign signatures
- CLI-first: every GUI action has a documented shell equivalent

## Seed data (auto-loaded on first backend boot)
- 12 workstations (mix of nixos/windows, offense/defense/analyst, online/drift/offline)
- 8 CVEs across critical/high/medium/low severity
- 5 signed releases across stable/beta/nightly channels
- Audit events for each workstation

## Test credentials
- Admin: `admin@secmaster.io` / `admin1234`

## Backlog (P0 → P2)
- **P0 (Phase 3):** GitHub Actions build pipeline + cosign signing job
- **P1 (Phase 5):** Live NVD CVE feed sync (currently seeded), CVE feed webhook
- **P1:** Reproducibility verification job (nix build --check on cron)
- **P1:** Container-based offense sandbox as fourth mode (recommended in problem statement)
- **P1:** MFA / WebAuthn for dashboard operators
- **P2:** Tool version diff / drift-diff inspector (UI stub in place)
- **P2:** Public beta docs site (mkdocs / Docusaurus)
- **P2:** mTLS for agent → dashboard (currently bearer token)

## Endpoints
Auth: `/api/auth/{register,login,logout,me,refresh}`
Fleet: `/api/workstations`, `/api/workstations/{id}`, `/api/workstations/{id}/switch-profile`
Enroll: `/api/enroll/generate`, `/api/agent/enroll`, `/api/agent/heartbeat`
CVE: `/api/cves`, `/api/cves/rescan`
Releases: `/api/releases`
Stats: `/api/stats/overview`
Audit: `/api/audit`
