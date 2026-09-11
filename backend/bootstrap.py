"""Bootstrap scripts served to workstations — enroll + install the heartbeat daemon."""
from __future__ import annotations

BASH = r'''#!/usr/bin/env bash
# Security Master agent bootstrap — enroll this host and install the heartbeat daemon.
# Usage: curl -sSL <dashboard>/api/agent/bootstrap.sh | ENROLL_TOKEN=... SM_HOSTNAME=... bash
set -euo pipefail

DASHBOARD="${SM_DASHBOARD:-__DASHBOARD__}"
: "${ENROLL_TOKEN:?ENROLL_TOKEN is required}"
SM_HOSTNAME="${SM_HOSTNAME:-${HOSTNAME:-$(hostname)}}"
INSTALL_DIR="${SM_INSTALL_DIR:-/opt/sec-master}"
STATE_DIR="${SM_STATE_DIR:-/var/lib/sec-master}"
INTERVAL="${SM_INTERVAL:-60}"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi
run_root() { if [ -n "$SUDO" ]; then sudo env "$@"; else env "$@"; fi; }

command -v python3 >/dev/null 2>&1 || { echo "[sec-master] python3 is required" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "[sec-master] curl is required" >&2; exit 1; }

OS_KIND="linux"
if [ -f /etc/NIXOS ]; then OS_KIND="nixos"; fi

echo "[sec-master] dashboard=$DASHBOARD host=$SM_HOSTNAME os=$OS_KIND"
$SUDO mkdir -p "$INSTALL_DIR" "$STATE_DIR"
curl -fsSL "$DASHBOARD/api/agent/agent.py" | $SUDO tee "$INSTALL_DIR/agent.py" >/dev/null
$SUDO chmod 755 "$INSTALL_DIR/agent.py"

run_root ENROLL_TOKEN="$ENROLL_TOKEN" SM_HOSTNAME="$SM_HOSTNAME" SM_STATE_DIR="$STATE_DIR" \
  python3 "$INSTALL_DIR/agent.py" --enroll --dashboard "$DASHBOARD" --os "$OS_KIND"

if [ "$OS_KIND" = "nixos" ]; then
  # /etc/systemd/system is store-managed on NixOS: run a transient unit now, persist via the flake module.
  $SUDO systemd-run --unit=sec-master-agent --property=Restart=always --property=RestartSec=15 \
    --setenv=SM_DASHBOARD="$DASHBOARD" --setenv=SM_STATE_DIR="$STATE_DIR" \
    python3 "$INSTALL_DIR/agent.py" --heartbeat --interval "$INTERVAL" || true
  cat <<EOF
[sec-master] transient unit started (sec-master-agent). To persist across reboots add to your flake:
  imports = [ security-master.nixosModules.agent ];
  services.sec-master-agent = { enable = true; dashboardUrl = "$DASHBOARD"; };
EOF
elif command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
  $SUDO tee /etc/systemd/system/sec-master-agent.service >/dev/null <<EOF
[Unit]
Description=Security Master fleet agent
After=network-online.target
Wants=network-online.target

[Service]
Environment=SM_DASHBOARD=$DASHBOARD
Environment=SM_STATE_DIR=$STATE_DIR
ExecStart=/usr/bin/env python3 $INSTALL_DIR/agent.py --heartbeat --interval $INTERVAL
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now sec-master-agent.service
  echo "[sec-master] agent installed as systemd service: sec-master-agent"
else
  echo "[sec-master] systemd not found. Start the daemon manually:"
  echo "  SM_DASHBOARD=$DASHBOARD SM_STATE_DIR=$STATE_DIR nohup python3 $INSTALL_DIR/agent.py --heartbeat --interval $INTERVAL &"
fi
echo "[sec-master] done. The host will appear in the fleet within one heartbeat."
'''

POWERSHELL = r'''#Requires -RunAsAdministrator
# Security Master agent bootstrap (Windows) — enroll this host and install the heartbeat task.
# Usage: $env:ENROLL_TOKEN="..."; $env:SM_HOSTNAME="..."; iwr <dashboard>/api/agent/bootstrap.ps1 -UseB | iex
$ErrorActionPreference = "Stop"
$Dashboard = if ($env:SM_DASHBOARD) { $env:SM_DASHBOARD } else { "__DASHBOARD__" }
if (-not $env:ENROLL_TOKEN) { throw "ENROLL_TOKEN environment variable is required" }
$Hostname = if ($env:SM_HOSTNAME) { $env:SM_HOSTNAME } else { $env:COMPUTERNAME }
$InstallDir = Join-Path $env:ProgramData "SecMaster"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) { throw "python not found. Install it first: winget install Python.Python.3.12" }

Write-Host "[sec-master] dashboard=$Dashboard host=$Hostname" -ForegroundColor Magenta
Invoke-WebRequest -UseBasicParsing "$Dashboard/api/agent/agent.py" -OutFile (Join-Path $InstallDir "agent.py")
Invoke-WebRequest -UseBasicParsing "$Dashboard/api/agent/SecurityMaster.psm1" -OutFile (Join-Path $InstallDir "SecurityMaster.psm1")

$env:SM_STATE_DIR = $InstallDir
$env:SM_HOSTNAME = $Hostname
& $py.Source (Join-Path $InstallDir "agent.py") --enroll --dashboard $Dashboard --os windows
if ($LASTEXITCODE -ne 0) { throw "enrollment failed (exit $LASTEXITCODE)" }

[Environment]::SetEnvironmentVariable("SM_DASHBOARD", $Dashboard, "Machine")
[Environment]::SetEnvironmentVariable("SM_STATE_DIR", $InstallDir, "Machine")

$agentPath = Join-Path $InstallDir "agent.py"
$action = New-ScheduledTaskAction -Execute $py.Source -Argument "`"$agentPath`" --heartbeat --interval 60 --dashboard $Dashboard"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "SecMasterAgent" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName "SecMasterAgent"
Write-Host "[sec-master] enrolled $Hostname and installed scheduled task SecMasterAgent" -ForegroundColor Green
'''


def render(script: str, dashboard: str) -> str:
    return script.replace("__DASHBOARD__", dashboard.rstrip("/"))
