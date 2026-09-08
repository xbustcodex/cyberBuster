{
  description = "Security Master — Cross-Platform Hardened Analyst Toolchain (Linux/NixOS profile engine)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    home-manager = {
      url = "github:nix-community/home-manager/release-24.11";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, home-manager, ... }@inputs:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; config.allowUnfree = true; };
    in
    {
      # Reusable NixOS module — turns any host into a Security Master workstation
      nixosModules.default = { config, lib, pkgs, ... }: {
        imports = [
          ./modules/hardening.nix
          ./modules/audit.nix
          ./modules/firewall.nix
        ];

        # Base toolchain — installed regardless of profile
        environment.systemPackages = with pkgs; [
          git age sops wireshark tcpdump mitmproxy vscode docker qemu
        ];

        # Profile specialisations — pick at bootloader
        specialisation = {
          offense.configuration = {
            imports = [ ./profiles/offense.nix ];
            system.nixos.tags = [ "offense" ];
          };
          defense.configuration = {
            imports = [ ./profiles/defense.nix ];
            system.nixos.tags = [ "defense" ];
          };
          analyst.configuration = {
            imports = [ ./profiles/analyst.nix ];
            system.nixos.tags = [ "analyst" ];
          };
        };

        # LUKS enforcement check runs at activation
        system.activationScripts.checkLuks.text = ''
          if ! ${pkgs.util-linux}/bin/lsblk -o TYPE | grep -q crypt; then
            echo "[sec-master] WARNING: no LUKS-encrypted volume detected on this system"
          fi
        '';

        # Agent daemon
        systemd.services.sec-master-agent = {
          description = "Security Master fleet reporting agent";
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            ExecStart = "${pkgs.python3}/bin/python3 /etc/sec-master/agent.py";
            Restart = "always";
            User = "sec-master";
          };
        };
      };

      # Bootstrapped host example
      nixosConfigurations.hardened-analyst = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ self.nixosModules.default ];
      };

      packages.${system}.default = pkgs.writeShellScriptBin "sec-master" ''
        exec ${pkgs.python3}/bin/python3 /etc/sec-master/cli.py "$@"
      '';
    };
}
