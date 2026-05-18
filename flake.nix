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
        playwrightRuntimeDeps = with pkgs; [
          alsa-lib
          at-spi2-atk
          at-spi2-core
          atk
          cairo
          cups
          dbus
          expat
          fontconfig
          freetype
          gdk-pixbuf
          glib
          gtk3
          libdrm
          libgbm
          libxkbcommon
          libxshmfence
          mesa
          nspr
          nss
          pango
          systemd
          libX11
          libXScrnSaver
          libXcomposite
          libXcursor
          libXdamage
          libXext
          libXfixes
          libXi
          libXrandr
          libXrender
          libXtst
          libxcb
        ];
      in
      {
        devShells.default =
          with pkgs;
          mkShell {
            LD_LIBRARY_PATH = lib.makeLibraryPath playwrightRuntimeDeps;

            packages = [
              nil
              just
              cargo-expand
              bacon
              esbuild
              nodejs
              cargo-dist
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
