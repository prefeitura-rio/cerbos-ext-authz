{
  description = "Envoy External Authorization Service for Cerbos PDP";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_24
            gcc
            docker
            docker-compose
            redis
            curl
            jq
            just
            delve
            gopls
            go-tools
            gotools
            golangci-lint
            grpcurl
            # Python dependencies for sandbox tools
            python3
            python3Packages.pip
            python3Packages.requests
            python3Packages.pyjwt
            python3Packages.cryptography
            python3Packages.fastapi
            python3Packages.uvicorn
          ];

          shellHook = ''
            echo "🚀 Envoy Cerbos PDP Authz Development Environment"
            echo "Available commands:"
            echo "  just run         - Run the service locally"
            echo "  just run-mock    - Run in mock mode"
            echo "  just build       - Build the binary"
            echo "  just docker-compose - Run with Docker Compose"
            echo "  just test-curl-http  - Test HTTP endpoint"
            echo "  just test-curl-grpc  - Test gRPC endpoint"
            echo ""
            echo "🐍 Python sandbox tools:"
            echo "  ./sandbox/ext_authz_test.py  - CLI authorization tester"
            echo "  ./sandbox/cerbos_check.py    - Direct Cerbos permission checker"
          '';
        };

        packages.default = pkgs.buildGoModule {
          pname = "cerbos-authz";
          version = "0.1.0";
          src = ./.;

          vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

          meta = with pkgs.lib; {
            description = "Envoy External Authorization Service for Cerbos PDP";
            homepage = "https://github.com/prefeitura-rio/cerbos-ext-authz";
            license = licenses.mit;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };
      }
    );
} 