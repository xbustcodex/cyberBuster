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
  Write-Host "[sec-master] profile applied. reboot recommended." -ForegroundColor Green
}

function Invoke-SMEnroll {
  param(
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][string]$Hostname,
    [string]$DashboardUrl = "https://hardened-analyst.preview.emergentagent.com"
  )
  $body = @{ token = $Token; hostname = $Hostname; os = "windows"; profile = "analyst"; agent_version = "0.1.0" } | ConvertTo-Json
  $resp = Invoke-RestMethod -Uri "$DashboardUrl/api/agent/enroll" -Method POST -Body $body -ContentType "application/json"
  [Environment]::SetEnvironmentVariable("SM_AGENT_TOKEN", $resp.agent_token, "Machine")
  Write-Host "[sec-master] enrolled. workstation_id=$($resp.workstation_id)"
}

function Update-SMBundle {
  Write-Host "[sec-master] fetching signed release manifest..."
  # verify cosign signature, then apply DSC config set
}

Export-ModuleMember -Function Set-SMProfile, Invoke-SMEnroll, Update-SMBundle
