#!/usr/bin/env bash
# Rebuilds the committed ceremony module. CI runs this and then `git diff --exit-code`,
# so the output has to be byte-identical everywhere: -trimpath drops paths, -s -w drops
# the build id's debug sections, and GOTOOLCHAIN pins the compiler to the go directive in
# go.mod rather than whatever is installed on the machine.
set -euo pipefail
cd "$(dirname "$0")/.."
GOTOOLCHAIN="go$(go list -m -f '{{.GoVersion}}')"
export GOTOOLCHAIN
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o internal/server/static/wasm/ceremony.wasm ./cmd/ceremony-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" internal/server/static/wasm/wasm_exec.js
ls -la internal/server/static/wasm/
