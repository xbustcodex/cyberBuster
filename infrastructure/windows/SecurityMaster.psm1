#Requires -Version 7.0
<#
.SYNOPSIS
  Security Master — Windows profile switcher (mirror of NixOS specialisation blocks).
.DESCRIPTION
  Set-SMProfile offense|defense|analyst
  Applies a DSC configuration set that swaps firewall rules, service state,
  and toolchain PATH. Analogous to nixos-rebuild switch --specialisation.
#>

$script:SM_PROFILES = @{
  offense = @{
    Firewall      = @{ DefaultInboundAction = "Allow"; AllowedApps = @("nmap","burp") }
    Services      = @{ Start = @("Tor","proxychains"); Stop = @("Wazuh") }
    WingetInstall = @("Rapid7.Metasploit","OWASP.ZAP","Ghidra")
  }
  defense = @{
    Firewall      = @{ DefaultInboundAction = "Block"; AllowedApps = @("wazuh-agent","osquery") }
    Services      = @{ Start = @("Sysmon","Wazuh","osqueryd"); Stop = @("Tor") }
    WingetInstall = @("Volatility.Volatility3","Velocidex.Velociraptor","osquery.osquery")
  }
  analyst = @{
    Firewall      = @{ DefaultInboundAction = "Block"; AllowedApps = @() }
    Services      = @{ Start = @("Docker","WSL"); Stop = @() }
    WingetInstall = @("Microsoft.VisualStudioCode","WiresharkFoundation.Wireshark","Git.Git")
  }
}

function Set-SMProfile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet("offense","defense","analyst")]
    [string]$Profile
  )
  $cfg = $script:SM_PROFILES[$Profile]
  Write-Host "[sec-master] switching to profile: $Profile" -ForegroundColor Magenta

  Set-NetFirewallProfile -All -DefaultInboundAction $cfg.Firewall.DefaultInboundAction

  foreach ($svc in $cfg.Services.Start) { Start-Service $svc -ErrorAction SilentlyContinue }
  foreach ($svc in $cfg.Services.Stop)  { Stop-Service  $svc -ErrorAction SilentlyContinue }

  foreach ($pkg in $cfg.WingetInstall)  { winget install --id $pkg --silent --accept-package-agreements }

  [Environment]::SetEnvironmentVariable("SM_PROFILE", $Profile, "Machine")
  $stateDir = if ($env:SM_STATE_DIR) { $env:SM_STATE_DIR } else { Join-Path $env:ProgramData "SecMaster" }
  New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
  Set-Content -Path (Join-Path $stateDir "profile") -Value $Profile -NoNewline
  Write-Host "[sec-master] profile applied. reboot recommended." -ForegroundColor Green
}

function Invoke-SMEnroll {
  <# Enroll this host. Prefer the bootstrap: iwr <dashboard>/api/agent/bootstrap.ps1 -UseB | iex #>
  param(
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][string]$Hostname,
    [Parameter(Mandatory)][string]$DashboardUrl
  )
  $env:ENROLL_TOKEN = $Token
  $env:SM_HOSTNAME = $Hostname
  $env:SM_DASHBOARD = $DashboardUrl
  Invoke-WebRequest -UseBasicParsing "$DashboardUrl/api/agent/bootstrap.ps1" | Select-Object -ExpandProperty Content | Invoke-Expression
}

function Update-SMBundle {
  <# Download the latest signed release bundle and verify it with cosign (keyless / GitHub OIDC). #>
  param(
    [Parameter(Mandatory)][string]$DashboardUrl,
    [string]$Repo = "xbustcodex/cyberBuster"
  )
  $token = [Environment]::GetEnvironmentVariable("SM_TOKEN", "Machine")
  $headers = @{}
  if ($token) { $headers["Authorization"] = "Bearer $token" }
  $releases = Invoke-RestMethod -Uri "$DashboardUrl/api/releases" -Headers $headers
  $latest = $releases | Where-Object { $_.source -eq "github" } | Select-Object -First 1
  if (-not $latest) { Write-Host "[sec-master] no GitHub releases synced yet" -ForegroundColor Yellow; return }
  Write-Host "[sec-master] latest release: $($latest.version) signature=$($latest.signature_status)"
  $bundle = $latest.assets | Where-Object { $_.name -like "*.tar.gz" } | Select-Object -First 1
  $sig    = $latest.assets | Where-Object { $_.name -like "*.bundle" } | Select-Object -First 1
  if (-not $bundle -or -not $sig) { Write-Host "[sec-master] release has no signed bundle asset" -ForegroundColor Yellow; return }
  $dl = Join-Path $env:TEMP "sec-master-release"
  New-Item -ItemType Directory -Force -Path $dl | Out-Null
  Invoke-WebRequest -UseBasicParsing $bundle.download_url -OutFile (Join-Path $dl $bundle.name)
  Invoke-WebRequest -UseBasicParsing $sig.download_url -OutFile (Join-Path $dl $sig.name)
  if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) { throw "cosign not found: winget install sigstore.cosign" }
  cosign verify-blob --bundle (Join-Path $dl $sig.name) `
    --certificate-identity-regexp "https://github.com/$Repo/" `
    --certificate-oidc-issuer https://token.actions.githubusercontent.com (Join-Path $dl $bundle.name)
  if ($LASTEXITCODE -ne 0) { throw "cosign verification FAILED for $($latest.version)" }
  Write-Host "[sec-master] signature verified. bundle at $dl" -ForegroundColor Green
}

Export-ModuleMember -Function Set-SMProfile, Invoke-SMEnroll, Update-SMBundle
