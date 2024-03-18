{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, gitignore, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustPlatform = pkgs.makeRustPlatform {
        cargo = rustToolchain;
        rustc = rustToolchain;
      };
    in
    {
      formatter.${system} = pkgs.nixpkgs-fmt;

      devShells.${system}.default = pkgs.mkShell {
        packages = [ rustToolchain ];
      };

      packages.${system}.default = rustPlatform.buildRustPackage rec {
        pname = "resolved";
        version = "0.0.0";

        src = gitignore.lib.gitignoreSource ./.;

        postInstall = ''
          cd config
          find . -type f -exec install -Dm 755 "{}" "$out/etc/resolved/{}" \;
        '';

        cargoLock = {
          lockFile = ./Cargo.lock;
        };

        doCheck = false;

        meta = {
          description = "A simple DNS server for home networks.";
          homepage = "https://github.com/barrucadu/resolved";
        };
      };
    };
}
