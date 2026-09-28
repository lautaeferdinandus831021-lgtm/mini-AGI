#!/usr/bin/env bash
#===============================================================================
# skills_gate.sh - security gate for agent skills, before they are installed.
#
# Policy: no agent skill enters this repository (or any agent that reads it)
# without a SkillSpector scan passing first. Agent skills execute with
# implicit trust inside coding agents; NVIDIA's own research (SkillSpector)
# found ~26% of community skills carrying vulnerabilities, so the scan runs
# BEFORE `skills add`, not after.
#
# Usage:
#   bash scripts/skills_gate.sh <path-or-git-url> [more targets...]
#   SCAN_ONLY=1 bash scripts/skills_gate.sh <target>   # report, never block
#
# What it does per target:
#   1. runs `skillspector scan <target> --no-llm` (static pass; the LLM stage
#      needs provider credentials and is off by default here)
#   2. saves the JSON report under .skillspector/
#   3. blocks HIGH/CRITICAL findings; MEDIUM/LOW are recorded as hardening
#      notes (NVIDIA's own catalog ships those) - SCAN_ONLY=1 downgrades
#      everything to report-only
#
# Fails closed: if skillspector is not on PATH, nothing is scanned and the
# gate exits 2 - an unscannable skill is an uninstallable skill.
#
# Install after a clean gate:
#   bash scripts/skills_gate.sh NVIDIA/skills && npx skills add NVIDIA/skills
#
# Install SkillSpector itself (Python 3.12+ via uv):
#   uv python install 3.12 && uv tool install \
#       git+https://github.com/lautaeferdinandus831021-lgtm/SkillSpector.git
#===============================================================================
set -u

SKILLSPECTOR="${SKILLSPECTOR_BIN:-skillspector}"
OUTDIR="${SKILLSPECTOR_OUTDIR:-.skillspector}"
SCAN_ONLY="${SCAN_ONLY:-0}"

mkdir -p "$OUTDIR"

if ! command -v "$SKILLSPECTOR" >/dev/null 2>&1; then
    echo "[gate] FAIL-CLOSED: '$SKILLSPECTOR' not found on PATH." >&2
    echo "[gate] install it first:  uv python install 3.12 && uv tool install \\" >&2
    echo "[gate]   git+https://github.com/lautaeferdinandus831021-lgtm/SkillSpector.git" >&2
    exit 2
fi

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <path-or-git-url> [more targets...]" >&2
    exit 2
fi

rc=0
for target in "$@"; do
    stamp="$(date +%Y%m%d-%H%M%S)"
    slug="$(printf '%s' "$target" | tr '/:.' '___')"
    report="$OUTDIR/${slug}-${stamp}.json"

    echo "[gate] scanning: $target"
    # shellcheck disable=SC2086
    if ! "$SKILLSPECTOR" scan "$target" --recursive --no-llm \
            --format json --output "$report"; then
        echo "[gate] BLOCKED (scanner error): $target" >&2
        echo "[gate] report: $report" >&2
        rc=1
        continue
    fi

    verdict="$(python3 - "$report" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
ra = r.get("risk_assessment", {})
issues = r.get("issues") or []
sev = (ra.get("max_issue_severity") or "NONE").upper()
score = ra.get("score", "?")
rec = ra.get("recommendation", "?")
# tiered policy: HIGH/CRITICAL findings block; MEDIUM/LOW are hardening
# notes NVIDIA itself ships - record them, let a human decide
blocked = sev in ("HIGH", "CRITICAL")
print(f"{len(issues)}|{score}|{rec}|{sev}|{'BLOCK' if blocked else 'PASS'}")
PY
)"
    n="$(echo "$verdict" | cut -d'|' -f1)"
    score="$(echo "$verdict" | cut -d'|' -f2)"
    rec="$(echo "$verdict" | cut -d'|' -f3)"
    sev="$(echo "$verdict" | cut -d'|' -f4)"
    action="$(echo "$verdict" | cut -d'|' -f5)"

    if [ "$action" = "BLOCK" ] && [ "$SCAN_ONLY" != "1" ]; then
        echo "[gate] BLOCKED: $n finding(s), max $sev, risk $score ($rec)"
        echo "[gate] report: $report"
        rc=1
    else
        echo "[gate] pass${n:+ ($n finding(s), max $sev - hardening notes)}: risk $score ($rec)"
        echo "[gate] report: $report"
    fi
done

if [ "$rc" -eq 0 ]; then
    echo "[gate] all targets clean - safe to install"
else
    echo "[gate] at least one target is blocked - do NOT install it" >&2
fi
exit "$rc"
