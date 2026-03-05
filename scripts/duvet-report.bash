#!/usr/bin/env bash
set -euo pipefail

# Run extract to download and cache the remote spec (uses config format).
duvet extract --config-path .duvet/config.toml \
  -f markdown \
  "https://raw.githubusercontent.com/aranya-project/aranya-docs/refs/heads/main/docs/multi-daemon-convergence-test.md" \
  2>/dev/null || true

# Strip YAML front matter from cached .txt specs so duvet's
# auto-detection sees a leading '#' and chooses the markdown parser.
find .duvet/specifications -name '*.txt' -print0 | while IFS= read -r -d '' f; do
  if head -1 "$f" | grep -q '^---$'; then
    awk 'BEGIN{n=0} /^---$/{n++; next} n>=2{print}' "$f" > "$f.tmp"
    mv "$f.tmp" "$f"
  fi
done

duvet report --config-path .duvet/config.toml
