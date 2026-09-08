{ config, lib, pkgs, ... }:
# ANALYST profile — daily driver: research, reversing, OSINT, malware triage inside VMs.
{
  environment.systemPackages = with pkgs; [
    ghidra radare2 cutter
    virtualbox qemu_kvm libvirt
    firefox chromium
    obsidian
  ];

  virtualisation.libvirtd.enable = true;
  virtualisation.docker.enable = true;

  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = false;
    settings.PermitRootLogin = "no";
  };

  users.motd = ''
    profile: ANALYST
    default posture · use VMs for untrusted samples
  '';
}
