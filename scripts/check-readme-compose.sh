#!/bin/sh
# Fails when README.md drifts from the files it shows inline:
#  - the fenced block after <!-- readme-sync: docker-compose.yml --> must be
#    byte-for-byte docker-compose.yml;
#  - every variable set in the block after <!-- readme-sync: env --> must exist
#    in .env.example.
set -eu
cd "$(dirname "$0")/.."

# block MARKER: the body of the first fenced block after the marker line.
block() {
	awk -v marker="<!-- readme-sync: $1 -->" '
		$0 == marker { armed = 1; next }
		armed && !inside && /^```/ { inside = 1; next }
		inside && /^```$/ { found = 1; exit }
		inside { print }
		END { exit found ? 0 : 1 }
	' README.md
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

block docker-compose.yml >"$tmp/compose" || {
	echo "README.md: no fenced block after <!-- readme-sync: docker-compose.yml -->" >&2
	exit 1
}
if ! cmp -s "$tmp/compose" docker-compose.yml; then
	echo "README.md's docker-compose.yml differs from the repository file:" >&2
	diff -u docker-compose.yml "$tmp/compose" >&2 || true
	exit 1
fi

block env >"$tmp/env" || {
	echo "README.md: no fenced block after <!-- readme-sync: env -->" >&2
	exit 1
}
missing=0
for name in $(sed -n 's/^\([A-Z_][A-Z0-9_]*\)=.*/\1/p' "$tmp/env"); do
	if ! grep -q "^$name=" .env.example; then
		echo "README.md's .env example sets $name, which .env.example does not document" >&2
		missing=1
	fi
done
[ "$missing" -eq 0 ] || exit 1
echo "README.md matches docker-compose.yml and .env.example"
