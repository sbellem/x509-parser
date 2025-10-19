{
  description = "Example Rust development environment for Zero to Nix";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0";
    rust-overlay.url = "https://flakehub.com/f/oxalica/rust-overlay/*";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      overlays = [
        (import rust-overlay)
        (final: prev: {
          rustToolchain = prev.rust-bin.stable.latest.default;
        })
      ];

      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs allSystems (
          system:
          f {
            pkgs = import nixpkgs { inherit overlays system; };
          }
        );
    in
    {
      devShells = forAllSystems (
        { pkgs }:
        {
          default = pkgs.mkShell {
            packages =
              (with pkgs; [
                # The package provided by our custom overlay. Includes cargo, Clippy, cargo-fmt,
                # rustdoc, rustfmt, and other tools.
                rustToolchain
                pkg-config
                systemd.dev
                openssl
                #udev
              ])
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs; [ libiconv ]);

            shellHook = ''
              echo "rust dev env for tropic01"
            '';
            #export PKG_CONFIG_PATH=${pkgs.libudev}/lib/pkgconfig${pkgs.stdenv.isLinux ? ":$PKG_CONFIG_PATH" : ""}
            #export CARGO_TARGET=$(rustc --print target-spec-json | ${pkgs.jq}/bin/jq -r .llvm_target)
            #echo "Default Cargo target set to: $CARGO_TARGET"
            #echo "Override with: export CARGO_BUILD_TARGET=<target>"
          };
        }
      );
    };
}
