#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PN=${PN:-$ROOT/build/pn}

[[ -x $PN ]] || {
    echo "ProxyNightmare binary is missing: $PN" >&2
    echo "Build it with: cmake -S '$ROOT' -B '$ROOT/build' && cmake --build '$ROOT/build'" >&2
    exit 2
}

count=0
while IFS= read -r scenario; do
    "$PN" check "$scenario"
    ((count += 1))
done < <(find "$ROOT/tests/scenarios" -type f -name '*.pn' -print | sort)

echo "PASS: validated $count ProxyNightmare scenarios"
