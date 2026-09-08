{ config, lib, pkgs, ... }:
# OFFENSE profile — red-team tooling, permissive network stack, MAC randomization ready.
{
  environment.systemPackages = with pkgs; [
    nmap burpsuite ffuf sqlmap impacket bloodhound
    metasploit ghidra radare2 crackmapexec
    aircrack-ng wifite kismet
    macchanger tor proxychains-ng
  ];

  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 4444 8080 8443 ];
    checkReversePath = false;   # tools need spoofed source packets
  };

  services.tor.enable = true;
  services.macchanger.enable = true;

  # Warning banner
  users.motd = ''
    ┌──────────────────────────────────────────────┐
    │ profile: OFFENSE                             │
    │ networking: permissive, MAC randomized       │
    │ do not use on production networks            │
    └──────────────────────────────────────────────┘
  '';
}
