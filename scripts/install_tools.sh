#!/usr/bin/env bash
set -euo pipefail

# Basic packages
sudo apt-get update -y
sudo apt-get install -y jq dnsutils nmap build-essential git curl unzip

# Install ProjectDiscovery tools (pin to versions for reproducibility)
export GO111MODULE=on
export GOBIN="$HOME/go/bin"
export PATH="$GOBIN:$PATH"

# Subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7
# Httpx
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.8
# Naabu
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.1
# Nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9
# Unfurl for URL parsing (optional)
go install github.com/tomnomnom/unfurl@latest

# Update nuclei templates (shallow) without telemetry
nuclei -update-templates -silent || true

mkdir -p results tmp
