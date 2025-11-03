{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [ 
    pkgs.go
    pkgs.inetutils
    pkgs.libpcap
  ];

  shellHook = ''
    export CGO_CFLAGS="-I${pkgs.libpcap}/include"
    export CGO_LDFLAGS="-L${pkgs.libpcap}/lib"
  '';
}
