{
  description = "GPG written in Go";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ self, ... }:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        {
          pkgs,
          config,
          self',
          inputs',
          lib,
          system,
          ...
        }:
        {
          packages = {
            default = self'.packages.bin;

            bin = pkgs.buildGoModule (finalAttrs: {
              pname = "gpg-go";
              version = self.shortRev or self.dirtyShortRev or "dev";
              src = ./.;
              vendorHash = "sha256-M8A6iqb2oETRDm0VKgKk1URoGNJ1jj680MbkC6zZWFk=";

              env.CGO_ENABLED = "0";

              ldflags = [
                "-s"
                "-w"
              ];

              meta.mainProgram = "gpg-go";
            });
          };

          devShells = {
            default = pkgs.mkShell {
              packages = [
                pkgs.go
              ];
            };
          };
        };
    };
}
