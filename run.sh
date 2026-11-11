#!/usr/bin/env bash
# Single-threaded Linux Agent entrypoint for Domain Hub & WHOIS/ICP workflow.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[环境错误] 未检测到 python3。请先安装 Python 3.9 及以上版本。" >&2
  exit 1
fi

export PYTHONUTF8=1
exec python3 -m agent_workflow.cli "$@"
