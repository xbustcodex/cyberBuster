{ config, lib, pkgs, ... }:
# DEFENSE / DFIR profile — blue-team tooling, AppArmor in permissive-log mode.
{
  environment.systemPackages = with pkgs; [
    volatility3 yara zeek suricata
    velociraptor osquery autopsy plaso
    chainsaw hayabusa wazuh-agent
  ];

  security.apparmor = {
    enable = true;
    killUnconfinedConfinables = false;   # log-only
  };

  services.suricata = {
    enable = true;
    settings = {
      af-packet = [ { interface = "eth0"; cluster-id = 99; } ];
    };
  };

  services.osquery.enable = true;

  networking.firewall.allowedTCPPorts = [ 1514 55000 ];  # wazuh manager

  users.motd = ''
    profile: DEFENSE / DFIR
    apparmor: permissive-log · suricata + osquery active
  '';
}
