#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-./install.sh}")" && pwd)"
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3,11))'; then
        PYTHON="$candidate"
        break
    fi
done
if [[ -z "$PYTHON" ]]; then
    echo 'Python 3.11 or newer is required.' >&2
    exit 1
fi
if [[ -f "$SCRIPT_DIR/install.py" ]]; then
    exec "$PYTHON" "$SCRIPT_DIR/install.py" "$@"
fi
# Piped bootstrap is pinned to the release; no mutable main download.
TEMP_INSTALLER="$(mktemp)"
trap 'rm -f -- "$TEMP_INSTALLER"' EXIT
curl --fail --silent --show-error --location \
    'https://raw.githubusercontent.com/j46871417-ui/devproxy/v2.0.1/install.py' -o "$TEMP_INSTALLER"
"$PYTHON" "$TEMP_INSTALLER" "$@"
