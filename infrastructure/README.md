# Security Master — Infrastructure Scaffolding

This directory contains **static, reference-quality** artifacts for the non-dashboard
portions of Security Master. They are the shape and structure of what the
production system will look like — they are not executed inside this dashboard
environment (which is a plain Linux container without Nix, DSC, or a real fleet).

```
infrastructure/
├── nix/                     # Phase 1 — NixOS flake, three profile specialisations
│   ├── flake.nix
│   └── profiles/
│       ├── offense.nix
│       ├── defense.nix
│       └── analyst.nix
├── windows/                 # Phase 2 — Windows parity via PowerShell DSC + Winget
│   ├── SecurityMaster.psm1  # Set-SMProfile / Invoke-SMEnroll / Update-SMBundle
│   └── profiles.dsc.ps1
└── agent/                   # Phase 4 — cross-platform reporting daemon
    └── agent.py             # --enroll · --heartbeat · --simulate N
```

## Quick reference — how these pieces plug into the dashboard

1. Operator generates a one-time token in the dashboard: `Enroll → generate`.
2. Operator copies the bash or powershell one-liner onto the target host.
3. That one-liner runs `agent.py --enroll` which exchanges the token for a
   persistent bearer, then loops on `--heartbeat`.
4. The dashboard reflects the new workstation, its profile, tool versions, and
   any CVE matches within one heartbeat cycle.

## Simulator (works right now)

The dashboard itself is fully populated with seeded fleet data on first boot,
but you can also spin up **live** fake workstations against the running API:

```
cd /app/infrastructure/agent
SM_DASHBOARD=http://localhost:8001 python3 agent.py --simulate 5
```

Each simulated agent goes through the real enrollment + heartbeat flow and
shows up in the fleet table.

## Non-goals of this scaffolding (documented honestly)

- **No kernel hardening.** Standard kernel + sane defaults only, so offensive
  tools keep working. Do not market this as "hardened against nation-state
  actors."
- **Windows parity ~70%.** Some Linux tooling (wifi stack, BloodHound Linux
  build, kernel-level YARA) has no clean Windows equivalent.
- **Rolling vs pinned:** default is pinned quarterly releases signed with
  cosign. Analysts don't need a rolling toolchain surprise on a Tuesday.
