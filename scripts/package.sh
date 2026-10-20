#!/usr/bin/env bash
# Builds the Chrome-loadable zip (extension files only: no tests, CLI or docs).
set -euo pipefail
cd "$(dirname "$0")/.."
v=$(node -p "require('./package.json').version")
out="dist/har-sanitizer-extension-v$v.zip"; mkdir -p dist; rm -f "$out"
zip -qr "$out" manifest.json icons src app devtools vendor -x "*.DS_Store"
echo "$out"
