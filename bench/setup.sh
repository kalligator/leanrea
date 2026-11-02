#!/usr/bin/env bash
# Prepares bench/work: installs rea-agents@6.5.0 and copies target test binaries.
# Supports macOS, Linux, or custom targets directory via $TARGETS_DIR.
set -euo pipefail
cd "$(dirname "$0")"

W="${LEANREA_WORK:-$PWD/work}"
mkdir -p "$W/targets" "$W/rea-install"

GH="$(command -v gh || true)"
[ -n "$GH" ] || { echo "gh CLI not found on PATH. Please install gh."; exit 1; }

# Target location discovery
if [ -n "${TARGETS_DIR:-}" ] && [ -d "$TARGETS_DIR" ]; then
  echo "Copying targets from custom directory: $TARGETS_DIR"
  cp -r "$TARGETS_DIR"/* "$W/targets/"
else
  # Check standard macOS path
  NOTION_MAC="/Applications/Notion.app/Contents/Resources"
  # Check standard Linux paths
  NOTION_LINUX="/opt/Notion/resources"
  [ -d "$NOTION_MAC" ] && NOTION="$NOTION_MAC"
  [ -d "$NOTION_LINUX" ] && NOTION="$NOTION_LINUX"
  NOTION="${NOTION:-${NOTION_DIR:-}}"

  if [ -n "$NOTION" ] && [ -f "$NOTION/app.asar" ]; then
    echo "Found Notion at: $NOTION"
    cp "$NOTION/app.asar" "$W/targets/"
    if [ -d "$NOTION/app.asar.unpacked" ]; then
      cp -r "$NOTION/app.asar.unpacked" "$W/targets/"
      NODE_MOD="$(find "$NOTION/app.asar.unpacked" -name mac_utils.node 2>/dev/null | head -1 || true)"
      [ -n "$NODE_MOD" ] && cp "$NODE_MOD" "$W/targets/"
    fi
  else
    echo "Note: Notion desktop app not found at default paths."
    echo "To test electron/native arms, set TARGETS_DIR=/path/to/targets or NOTION_DIR=/path/to/resources"
  fi
  cp "$GH" "$W/targets/gh"
fi

# Install REA baseline MCP if npm is available
if command -v npm >/dev/null 2>&1; then
  echo "Installing rea-agents baseline..."
  (cd "$W/rea-install" && npm init -y >/dev/null 2>&1 && npm install rea-agents@6.5.0 --ignore-scripts >/dev/null 2>&1 || true)
  if [ -f "$W/rea-install/node_modules/rea-agents/scripts/rea.mjs" ]; then
    node -e 'const [,p,o]=process.argv;require("fs").writeFileSync(o,JSON.stringify({mcpServers:{rea:{command:"node",args:[p,"--mcp"]}}}))' "$W/rea-install/node_modules/rea-agents/scripts/rea.mjs" "$W/rea-mcp.json"
  fi
fi

echo "Benchmark environment ready in: $W"
