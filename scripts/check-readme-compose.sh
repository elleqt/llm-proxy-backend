#!/bin/sh
# Fails when README.md drifts from the compose file it shows inline: the fenced
# block after <!-- readme-sync: docker-compose.minimal.yml --> must be
# byte-for-byte docker-compose.minimal.yml.
set -eu
cd "$(dirname "$0")/.."

file=docker-compose.minimal.yml
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# The body of the first fenced block after the marker line.
awk -v marker="<!-- readme-sync: $file -->" '
	$0 == marker { armed = 1; next }
	armed && !inside && /^```/ { inside = 1; next }
	inside && /^```$/ { found = 1; exit }
	inside { print }
	END { exit found ? 0 : 1 }
' README.md >"$tmp" || {
	echo "README.md: no fenced block after <!-- readme-sync: $file -->" >&2
	exit 1
}
if ! cmp -s "$tmp" "$file"; then
	echo "README.md's $file differs from the repository file:" >&2
	diff -u "$file" "$tmp" >&2 || true
	exit 1
fi
echo "README.md matches $file"
