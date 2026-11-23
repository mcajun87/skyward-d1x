#!/usr/bin/env bash
# Keep only the phones this fork supports. The upstream repository adapts a
# new Xiaomi phone every few weeks; without this, a sync would bring every
# one of them back into devices/ and the build matrix would try to build
# recoveries for phones this fork does not carry stock images for.
set -euo pipefail

if [ ! -f devices/supported.txt ]; then
  echo "devices/supported.txt is missing" >&2
  exit 1
fi

keep="$(grep -v '^#' devices/supported.txt | tr -d '[:space:]')"
echo "keeping devices: $(echo "$keep" | tr '\n' ' ')"

for file in devices/*.toml; do
  [ -e "$file" ] || continue
  name="$(basename "$file" .toml)"
  if ! printf '%s\n' "$keep" | grep -qx "$name"; then
    echo "removing $file"
    git rm -q --ignore-unmatch "$file" 2>/dev/null || rm -f "$file"
  fi
done
