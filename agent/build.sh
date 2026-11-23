#!/usr/bin/env bash
# Builds the agent for Windows (production target) plus macOS/Linux (dry-run demos).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/killswitch-agent.exe .
GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/killswitch-agent-macos-arm64 .
GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/killswitch-agent-macos-intel .
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/killswitch-agent-linux-amd64 .
ls -lh dist
