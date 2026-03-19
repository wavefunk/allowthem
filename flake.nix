{
  description = "Rust devshell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };
        toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        beads-latest = (pkgs.beads.override {
          buildGoModule = pkgs.buildGoModule.override { go = pkgs.go_1_26; };
        }).overrideAttrs (old: rec {
          version = "0.60.0";
          src = pkgs.fetchFromGitHub {
            owner = "steveyegge";
            repo = "beads";
            rev = "v${version}";
            hash = "sha256-z3EDtaBHB3ltPRT7vuBFURD7UwgAJBXAPozRnkjejeU=";
          };
          vendorHash = "sha256-1BJsEPP5SYZFGCWHLn532IUKlzcGDg5nhrqGWylEHgY=";
          doCheck = false;
        });
      in
      {
        devShells.default =
          with pkgs;
          mkShell {
            packages = [
              nil
              just
              cargo-expand
              bacon
              claude-code
              cargo-dist
              nodejs_22
              dotnet-sdk_8
              dolt
              beads-latest
            ];

            buildInputs = [
              openssl
              pkg-config
              toolchain
            ];
          };
      }
    );
}
