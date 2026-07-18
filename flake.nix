{
  description = "tunmux - WireGuard config-file VPN CLI (macOS)";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-25.11";
    devshell.url = "github:numtide/devshell";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, flake-utils, devshell, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import rust-overlay)
            devshell.overlays.default
          ];
        };

        common-toolchain = import ./nix/common-toolchain.nix { inherit pkgs; };
      in
      {
        devShells = {
          default = pkgs.devshell.mkShell {
            name = "tunmux";
            packages = [ common-toolchain.rust-toolchain-base ] ++ common-toolchain.commonPackages;
          };
        };
      }
    );
}
