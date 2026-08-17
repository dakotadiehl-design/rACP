#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/tools/wireshark/acp.lua"
if [[ "$(uname -s)" == "Darwin" ]]; then
  DEST="${HOME}/.config/wireshark/plugins"
else
  DEST="${HOME}/.local/lib/wireshark/plugins"
fi
mkdir -p "$DEST"
cp "$SRC" "$DEST/acp.lua"
echo "Installed $DEST/acp.lua"
