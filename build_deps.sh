#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

NCC_VERSION=0.38.1 # pinned, the build must not change because a new version was published

npm ci --ignore-scripts
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
npx --yes "@vercel/ncc@$NCC_VERSION" build --minify node_modules/qrcode/ -o "$out"
mv "$out/index.js" dist/qrcode.js
echo "dist/qrcode.js rebuilt"
