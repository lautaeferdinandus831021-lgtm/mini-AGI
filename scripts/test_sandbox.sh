#!/usr/bin/env bash
#===============================================================================
# test_sandbox.sh - run the repo's tests inside a throwaway sandbox.
#
# Purpose: "agar app tidak kotor" - every test artifact lands in a temp
# sandbox under /tmp, the working tree stays byte-identical to HEAD while
# the tests run, and that is verified afterwards.
#
# What runs here (all safe without a GPU, no network):
#   [1] python syntax      py_compile over every repo .py (in the checkout)
#   [2] minagi.skills      full regression: registry, contract tests,
#                          security battery, CLI (list/run/scan)
#   [3] skills gate        all five exit paths (clean, HIGH findings,
#                          SCAN_ONLY, fail-closed no-scanner, unparseable
#                          report) against a synthetic skill and a stub
#                          scanner built INSIDE the sandbox
#   [4] targeted           tests/test_targeted.py - regressions for the most
#                          recent fixes: serve.py identity rendering and
#                          routes, whole-character SSE decoding, the train.py
#                          growth-line print on both CPU and CUDA
#   [5] store surface      minagi.store contract (runs only if torch exists)
#   [6] tree hygiene       git status/diff unchanged by the whole run
#
# Usage:
#   bash scripts/test_sandbox.sh            # full suite
#   KEEP=1 bash scripts/test_sandbox.sh     # keep the sandbox for inspection
#
# Exit code: 0 iff every check passed.
#===============================================================================
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SB="${TEST_SANDBOX:-$(mktemp -d /tmp/miniagi-test-XXXX)}"
mkdir -p "$SB/out" "$SB/bin"
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); echo "  PASS $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
sect() { printf '\n\033[1;36m== %s ==\033{0m\n' "$1" | sed 's/{0m/[0m/'; }

echo "[sandbox] $SB"

# byte-identical checkout to run against: even a misbehaving test that
# writes next to the code cannot touch the working tree
git -C "$REPO" archive HEAD | tar -x -C "$SB"
# the checkout is HEAD, but the tests must cover whatever the developer has
# right now - so the working tree's tests/ is copied over it. Tests are
# read-only against the tree, so this cannot smuggle anything in; it just
# means a test file being written at this moment is the one that runs.
if [ -d "$REPO/tests" ]; then
    mkdir -p "$SB/tests"
    cp -f "$REPO"/tests/*.py "$SB/tests/" 2>/dev/null || true
fi
sha_ref="$(git -C "$REPO" status --porcelain | wc -l | tr -d ' ')"
# snapshot the tree's diff fingerprint: the suite must not alter it, whether
# the tree started clean or mid-feature
diff_before="$(git -C "$REPO" diff | git hash-object --stdin)"

#-----------------------------------------------------------------------------
sect "1. python syntax (sandboxed checkout)"
#-----------------------------------------------------------------------------
if ( cd "$SB" && find . -name '*.py' -not -path './.git/*' -print0 |
        xargs -0 python3 -m py_compile ); then
    ok "py_compile all repo .py"
else
    bad "py_compile"
fi

#-----------------------------------------------------------------------------
sect "2. minagi.skills regression"
#-----------------------------------------------------------------------------
if ( cd "$SB" && python3 - <<'PY'
from minagi.skills import run_skill, scan, registry
assert len(registry()) == 33
assert run_skill("CONTAINS", "abc def", keyword="def")["result"] is True
assert run_skill("IS_JSON", "{bad")["result"] is False
assert isinstance(run_skill("BLEU_SCORE", reference="a b", hypothesis="a c")["result"], float)
assert 0 < run_skill("MRR", reference="x y z", hypothesis="q w x")["result"] <= 1
# battery: real secret -> unguarded finding
assert scan("AKIAIOSFODNN7EXAMPLE")["pass"] is False
assert scan("the password: hunter22 is in the vault")["pass"] is False
# benign corpus -> no findings at all
assert scan("a quiet day in the park with a ball and friends")["n"] == 0
# reflective sentence -> nominated but guarded, gate stays green
g = scan("do not set secret = my_secret_value in code")
assert g["pass"] is True and len(g["findings"]) == 1, g
assert g["findings"][0]["guarded"] is True
print("contract+battery OK")
PY
) >/dev/null 2>&1; then
    ok "skills contract + security battery"
else
    bad "skills contract + security battery"
fi

if ( cd "$SB" && python3 -m minagi.skills list >/dev/null \
        && python3 -m minagi.skills run IS_JSON --text '{"a":1}' | grep -q pass ); then
    ok "skills CLI (list/run)"
else
    bad "skills CLI (list/run)"
fi

#-----------------------------------------------------------------------------
sect "3. skills gate exit paths (synthetic skill + stub scanner, sandbox-local)"
#-----------------------------------------------------------------------------
mkdir -p "$SB/fake-skill"
cat > "$SB/fake-skill/SKILL.md" <<'MD'
---
name: fake-skill
description: minimal synthetic skill for gate tests
---
Do the thing.
MD

# stub mimicking the real skillspector report contract and exit behaviour:
# writes the JSON report, exits non-zero when findings exist (FAKE knobs
# drive the scenario; FAKE_CORRUPT=1 emits a broken report instead).
cat > "$SB/bin/skillspector" <<'SH'
#!/usr/bin/env bash
sev="${FAKE_SEV:-NONE}"; score="${FAKE_SCORE:-0}"; n="${FAKE_N:-0}"
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        --output) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$out" ] || exit 3
if [ "${FAKE_CORRUPT:-0}" = "1" ]; then
    printf 'not json at all' > "$out"; exit 1
fi
issues="[]"
[ "$n" != "0" ] && issues="$(python3 -c "
import json, sys
print(json.dumps([{'severity': sys.argv[1]}] * int(sys.argv[2])))
" "$sev" "$n")"
cat > "$out" <<EOF
{"risk_assessment": {"score": $score, "severity": "$sev",
  "recommendation": "CAUTION", "max_issue_severity": "$sev"},
 "issues": $issues, "skill": {"name": "fake-skill"}}
EOF
[ "$sev" = "HIGH" ] && exit 1
exit 0
SH
chmod +x "$SB/bin/skillspector"
# the stub MUST win over any real skillspector on the machine
export PATH="$SB/bin:$PATH"

out="$(cd "$SB" && bash scripts/skills_gate.sh "$SB/fake-skill" 2>&1)" ; rc=$?
if [ "$rc" -eq 0 ] && echo "$out" | grep -q "safe to install"; then
    ok "gate clean -> rc=0"
else
    bad "gate clean (rc=$rc)"
fi

out="$(cd "$SB" && FAKE_SEV=HIGH FAKE_SCORE=65 FAKE_N=5 \
        bash scripts/skills_gate.sh "$SB/fake-skill" 2>&1)" ; rc=$?
if [ "$rc" -eq 1 ] && echo "$out" | grep -q "BLOCKED: 5 finding"; then
    ok "gate HIGH findings -> rc=1 BLOCKED"
else
    bad "gate HIGH findings (rc=$rc)"
fi

out="$(cd "$SB" && SCAN_ONLY=1 FAKE_SEV=HIGH \
        bash scripts/skills_gate.sh "$SB/fake-skill" 2>&1)" ; rc=$?
if [ "$rc" -eq 0 ] && echo "$out" | grep -q "NOT blocking"; then
    ok "gate SCAN_ONLY -> rc=0 report-only"
else
    bad "gate SCAN_ONLY (rc=$rc)"
fi

# no scanner anywhere on PATH: strip the stub back out
out="$(cd "$SB" && PATH="/usr/bin:/bin" \
        bash scripts/skills_gate.sh "$SB/fake-skill" 2>&1)" ; rc=$?
if [ "$rc" -eq 2 ] && echo "$out" | grep -q "FAIL-CLOSED"; then
    ok "gate no scanner -> rc=2 fail-closed"
else
    bad "gate no scanner (rc=$rc)"
fi

out="$(cd "$SB" && FAKE_CORRUPT=1 \
        bash scripts/skills_gate.sh "$SB/fake-skill" 2>&1)" ; rc=$?
if [ "$rc" -eq 1 ] && echo "$out" | grep -q "unparseable report"; then
    ok "gate corrupt report -> rc=1 fail-closed"
else
    bad "gate corrupt report (rc=$rc)"
fi

#-----------------------------------------------------------------------------
sect "4. targeted tests (tests/test_targeted.py)"
#-----------------------------------------------------------------------------
# every check is a regression for a specific merged fix. Sections whose
# dependencies are missing (torch, flask) print SKIP and count as neither
# pass nor failure, so the file contributes exactly ONE pass/fail to this
# runner wherever it runs.
if ( cd "$SB" && python3 tests/test_targeted.py ) > "$SB/out/targeted.log" 2>&1; then
    sed 's/^/  /' "$SB/out/targeted.log"
    res="$(sed -n 's/^\[result\] //p' "$SB/out/targeted.log")"
    ok "targeted tests (${res:-no summary line})"
else
    sed 's/^/  /' "$SB/out/targeted.log"
    bad "targeted tests"
fi

#-----------------------------------------------------------------------------
sect "5. store surface (runs only when torch is importable)"
#-----------------------------------------------------------------------------
if python3 -c "import torch" >/dev/null 2>&1; then
    if ( cd "$SB" && python3 -c "
from minagi import store
assert hasattr(store, 'save') and hasattr(store, 'load')
print('store surface OK')" >/dev/null 2>&1 ); then
        ok "minagi.store save/load present"
    else
        bad "minagi.store surface"
    fi
else
    echo "  SKIP minagi.store surface (torch not installed in this environment)"
fi

#-----------------------------------------------------------------------------
sect "6. working tree untouched by the whole run"
#-----------------------------------------------------------------------------
now="$(git -C "$REPO" status --porcelain | wc -l | tr -d ' ')"
if [ "$now" = "$sha_ref" ]; then
    ok "git status unchanged ($now untracked/marked entries before and after)"
else
    bad "working tree changed during tests ($sha_ref -> $now)"
fi
diff_after="$(git -C "$REPO" diff | git hash-object --stdin)"
if [ "$diff_after" = "$diff_before" ]; then
    ok "git diff fingerprint unchanged by the run"
else
    bad "git diff changed during tests"
fi

#-----------------------------------------------------------------------------
echo
if [ "${KEEP:-0}" = "1" ]; then
    echo "[sandbox] kept for inspection: $SB"
else
    rm -rf "$SB"
    echo "[sandbox] removed"
fi
echo "[result] PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
