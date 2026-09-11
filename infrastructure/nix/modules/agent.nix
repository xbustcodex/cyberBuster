{ config, lib, pkgs, ... }:
let
  cfg = config.services.sec-master-agent;
in
{
  options.services.sec-master-agent = {
    enable = lib.mkEnableOption "Security Master fleet reporting agent";
    dashboardUrl = lib.mkOption {
      type = lib.types.str;
      description = "Base URL of the Security Master dashboard (no trailing slash).";
    };
    agentScript = lib.mkOption {
      type = lib.types.path;
      default = ../../agent/agent.py;
      description = "Path to agent.py (defaults to the copy shipped in this flake).";
    };
    interval = lib.mkOption {
      type = lib.types.int;
      default = 60;
      description = "Heartbeat interval in seconds.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.sec-master-agent = {
      description = "Security Master fleet agent";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      # nixos-rebuild is needed so the agent can apply `--specialisation <profile>` switches
      path = [ pkgs.nixos-rebuild pkgs.nix pkgs.git ];
      environment = {
        SM_DASHBOARD = cfg.dashboardUrl;
        SM_STATE_DIR = "/var/lib/sec-master";
      };
      serviceConfig = {
        ExecStart = "${pkgs.python3}/bin/python3 ${cfg.agentScript} --heartbeat --interval ${toString cfg.interval}";
        Restart = "always";
        RestartSec = 15;
        StateDirectory = "sec-master";
      };
    };
  };
}
