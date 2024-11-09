{ pkgs, ... }:

{
  languages.rust.enable = true;
  packages = [ pkgs.cargo-watch ];
  scripts.wr.exec = "cargo watch -c -x run";
}
