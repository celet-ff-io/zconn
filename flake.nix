{
  description = "zconn";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, ... }@inputs:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forEachSupportedSystem =
        f:
        inputs.nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            inherit system;
            pkgs = import inputs.nixpkgs {
              inherit system;
            };
          }
        );
    in
    {
      devShells = forEachSupportedSystem (
        { pkgs, system }:
        let
          rustcSysroot = pkgs.symlinkJoin {
            name = "rustc-sysroot-with-completion";
            paths = [ pkgs.rustc.unwrapped ];
            postBuild = ''
              mkdir -p $out/share/zsh/site-functions
              install ${pkgs.cargo}/share/zsh/site-functions/_cargo $out/share/zsh/site-functions/
            '';
          };
        in
        {
          default = pkgs.mkShellNoCC {
            packages = with pkgs; [
              cargo
              (symlinkJoin {
                name = "rustc-with-completion";
                paths = [ rustc ];
                nativeBuildInputs = [ makeWrapper ];
                postBuild = ''
                  rm $out/bin/rustc
                  makeWrapper ${rustc}/bin/rustc $out/bin/rustc \
                    --add-flags "--sysroot=${rustcSysroot}"
                '';
              })
              rustc
              rust-analyzer
              rustfmt
              clippy
            ];
          };
        }
      );
    };
}
