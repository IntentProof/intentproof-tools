#!/usr/bin/env bash
# Regression test: EXCLUDE_PATH_FRAGMENTS must apply to every profile line.
set -euo pipefail

profile="$(mktemp)"
exclude="$(mktemp)"
trap 'rm -f "$profile" "$exclude"' EXIT

cat >"$profile" <<'EOF'
mode: set
example.com/pkg/jcs.go:1.1,2.1 1 1
example.com/pkg/jcs.go:3.1,4.1 1 0
example.com/pkg/main.go:1.1,2.1 2 2
example.com/pkg/main.go:3.1,4.1 2 0
EOF

printf '%s\n' "/jcs.go" >"$exclude"

read -r covered total <<EOF
$(awk -v exclude_file="$exclude" '
  BEGIN {
    while ((getline line < exclude_file) > 0) {
      if (line != "") excl[++n] = line
    }
    close(exclude_file)
  }
  function excluded(path,   i) {
    for (i = 1; i <= n; i++) {
      if (index(path, excl[i]) > 0) return 1
    }
    return 0
  }
  NR > 1 {
    path = $1
    sub(/:.*$/, "", path)
    if (n > 0 && excluded(path)) next
    stmts = $(NF - 1) + 0
    cnt = $NF + 0
    total += stmts
    if (cnt > 0) covered += stmts
  }
  END { print covered + 0, total + 0 }
' "$profile")
EOF

if [[ "$covered" != "2" || "$total" != "4" ]]; then
  echo "FAIL: expected 2/4 covered after exclude, got ${covered}/${total}" >&2
  exit 1
fi

echo "PASS: exclude patterns apply on every profile line"
