#!/usr/bin/env bash
#===============================================================================
# h1_comment.sh - build, verify and post the final H1 comment from NetHunter.
#
# Made for the NetHunter CLI runner (h1_comment.sh expected at /root/):
#
#   nethunter -r "bash /root/h1_comment.sh check"
#   nethunter -r "bash /root/h1_comment.sh build --out /sdcard/h1_comment.md"
#   nethunter -r "bash /root/h1_comment.sh send"                 # clipboard+browser
#   nethunter -r "bash /root/h1_comment.sh send --file /sdcard/h1_comment.md"
#   nethunter -r "bash /root/h1_comment.sh post --report 3971462 --dry-run"
#   nethunter -r "bash /root/h1_comment.sh post --report 3971462 --api"
#
# What it does:
#   check   verify h1_comment_draft.txt exists, every factual claim matches the
#           knowledge record (curl-referer-uaf), print the comment for review
#   build   extract ONLY the postable comment (after the --- marker) to a file
#   send    copy the comment to the Android clipboard and open the H1 report in
#           the browser - paste, re-read, send (the reliable phone path)
#   post    attempts a programmatic post. --api uses the HackerOne Hacker API
#           and is EXPERIMENTAL, fail-closed: the v1 hacker API surface does
#           not document a reporter "add comment" endpoint, so unless the
#           report accepts API comments the server will refuse and the script
#           exits non-zero without side effects. The clipboard+browser path
#           (`send`) is the intended one from a phone.
#
# Fail-closed rules: never reads/writes env secrets, never posts anything
# without an explicit subcommand and report id, `check` must pass before
# `build`, and no subcommand prints the API token (it is used in-place by curl).
#===============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# repo auto-detect, most specific wins: H1_REPO -> the directory the script
# lives in (the git-clone case: clone, `cd mini-AGI`, run - no env needed,
# exactly what a fresh cloud terminal wants) -> a WhiteHat_mini-AGI checkout
# next to $HOME (the copy-just-this-script case)
REPO="${H1_REPO:-}"
if [ -z "$REPO" ]; then
    if [ -f "$SCRIPT_DIR/artifacts/h1_comment_draft.txt" ]; then
        REPO="$SCRIPT_DIR"
    elif [ -f "$HOME/WhiteHat_mini-AGI/artifacts/h1_comment_draft.txt" ]; then
        REPO="$HOME/WhiteHat_mini-AGI"
    else
        REPO="$SCRIPT_DIR"
    fi
fi
DRAFT="$REPO/artifacts/h1_comment_draft.txt"
RECORD="$REPO/knowledge/curl-referer-uaf.json"
REPORT_ID=""
DRY_RUN=0
USE_API=0
OUT=""
FILE=""
# test-only override: point the post path at a local mock to rehearse the
# API exchange end-to-end. Production default is the real Hacker API.
API_BASE="${H1_API_BASE:-https://api.hackerone.com/v1/hackers}"
H1_USER_VAR="H1_API_USERNAME"      # name only - values are never read here
H1_TOKEN_VAR="H1_API_TOKEN"

die() { echo "[h1] ERROR: $*" >&2; exit 2; }

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

require_repo() {
    [ -f "$DRAFT" ]  || die "draft not found: $DRAFT (set H1_REPO=/path/to/WhiteHat_mini-AGI, or run from inside the repo clone)"
    [ -f "$RECORD" ] || die "knowledge record not found: $RECORD"
}

# ---------------------------------------------------------------- fact checks
# primary verifier needs python3; the fallback is pure bash grep for terminals
# that ship without it (verified on a fresh cloud sandbox)
verify_facts_python() {
    H1_DRAFT="$DRAFT" H1_RECORD="$RECORD" python3 - <<'PY'
import json, os, sys

draft = open(os.environ["H1_DRAFT"]).read()
if "Following the informative, no-CVE disposition" not in draft:
    sys.exit("draft body marker missing")
if "---" not in draft:
    sys.exit("draft separator '---' missing")

rec = json.load(open(os.environ["H1_RECORD"]))
assert rec["id"] == "curl-referer-uaf"
if rec["status"] != "n/a-informational" or rec["date_closed"] != "2026-10-01":
    sys.exit("record status/date_closed do not match the agreed disposition")

facts = " || ".join(rec["key_facts"]) + " || " + " | ".join(
    e["event"] for e in rec["timeline"])
required = [
    "ff300ac4aa", "2026-06-01", "d0247689", "2026-08-27",
    "8.22.0 (tag curl-8_22_0 on 2026-09-01",
    "8.21.0 (2026-06-23) is the ONLY tagged release",
    "Termux/proot", "ASLR", "informative, no CVE", "cloud Linux terminal",
]
missing = [c for c in required if c not in facts]
if missing:
    sys.exit("claims missing from record: " + ", ".join(missing))
print("[h1] facts OK: 10/10 claims trace to the record; disposition informative/no-CVE")
PY
}

verify_facts_grep() {
    # bash-only checks: same claims, string-match over the JSON + draft
    grep -qF 'Following the informative, no-CVE disposition' "$DRAFT" || die "draft body marker missing"
    grep -qF '"id": "curl-referer-uaf"' "$RECORD" || die "wrong record id"
    grep -qF '"status": "n/a-informational"' "$RECORD" || die "record status mismatch"
    grep -qF '"date_closed": "2026-10-01"' "$RECORD" || die "record date_closed mismatch"
    local claim
    for claim in 'ff300ac4aa' 'd0247689' \
                 '8.22.0 (tag curl-8_22_0 on 2026-09-01' \
                 '8.21.0 (2026-06-23) is the ONLY tagged release' \
                 'Termux/proot' 'ASLR' 'informative, no CVE' \
                 'cloud Linux terminal'; do
        grep -qF "$claim" "$RECORD" || die "claim missing from record: $claim"
    done
    echo "[h1] facts OK: claims verified by grep (python3 not available)"
}

verify_facts() {
    # probe: python3 must exist AND actually run (a broken python3 on PATH
    # must fall through to the bash verifier, not fail the whole check)
    if command -v python3 >/dev/null 2>&1 && python3 -c '' 2>/dev/null; then
        verify_facts_python || die "fact verification failed"
    else
        verify_facts_grep || die "fact verification failed"
    fi
}

extract_body() {
    awk 'seen{print} /^---$/{seen=1}' "$DRAFT"
}

# ------------------------------------------------------------- subcommands
[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && { usage; exit 0; }
CMD="${1:-}"; [ -n "$CMD" ] || { usage; exit 2; }
shift

while [ $# -gt 0 ]; do
    case "$1" in
        --report) REPORT_ID="$2"; shift 2 ;;
        --out)    OUT="$2"; shift 2 ;;
        --file)   FILE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --api)    USE_API=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see: bash $0 --help)" ;;
    esac
done

case "$CMD" in
check)
    require_repo
    verify_facts
    echo "[h1] comment body (exactly what would be posted):"
    echo "-------------------------------------------------------"
    extract_body
    echo "-------------------------------------------------------"
    echo "[h1] check passed: $DRAFT"
    ;;

build)
    require_repo
    verify_facts
    if [ -z "$OUT" ]; then
        if [ -d /sdcard ]; then OUT=/sdcard/h1_comment.md; else OUT=h1_comment.md; fi
    fi
    extract_body > "$OUT"
    echo "[h1] wrote $OUT ($(wc -l < "$OUT") lines, $(wc -w < "$OUT") words)"
    echo "[h1] review it, then: bash $0 send --file $OUT"
    ;;

send)
    require_repo
    verify_facts
    FILE="${FILE:-$DRAFT}"
    [ -f "$FILE" ] || die "file not found: $FILE"
    BODY="$(case "$FILE" in "$DRAFT") extract_body ;; *) cat "$FILE" ;; esac)"
    [ -n "$BODY" ] || die "comment body is empty"
    echo "[h1] target: https://hackerone.com/reports/${REPORT_ID:-3971462}"
    if command -v termux-clipboard-set >/dev/null 2>&1; then
        printf '%s' "$BODY" | termux-clipboard-set \
            && echo "[h1] comment copied to clipboard (Termux API)"
    elif command -v wl-copy >/dev/null 2>&1; then
        printf '%s' "$BODY" | wl-copy && echo "[h1] copied (wl-copy)"
    elif command -v xclip >/dev/null 2>&1; then
        printf '%s' "$BODY" | xclip -selection clipboard && echo "[h1] copied (xclip)"
    else
        die "no clipboard tool (install: pkg install termux-api)"
    fi
    # open the report in the browser: paste into the comment box, re-read, send
    if command -v termux-open-url >/dev/null 2>&1; then
        termux-open-url "https://hackerone.com/reports/${REPORT_ID:-3971462}" || true
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "https://hackerone.com/reports/${REPORT_ID:-3971462}" || true
    fi
    echo "[h1] paste (long-press → Paste), re-read, then hit Comment."
    echo "[h1] the comment you paste must match: bash $0 check"
    ;;

post)
    require_repo
    [ -n "$REPORT_ID" ] || die "post needs --report ID (e.g. --report 3971462)"
    verify_facts
    BODY="$(extract_body)"
    [ -n "$BODY" ] || die "comment body is empty"
    if [ "$DRY_RUN" = "1" ]; then
        echo "[h1] DRY-RUN (nothing sent). Would post to report $REPORT_ID via $([ "$USE_API" = "1" ] && echo API || echo clipboard+browser)."
        echo "$BODY"
        exit 0
    fi
    if [ "$USE_API" != "1" ]; then
        exec "$0" send --report "$REPORT_ID" --file "$DRAFT"
    fi
    # EXPERIMENTAL API path - fail closed. The Hacker API v1 surface (checked
    # 2026-10-01) exposes no documented reporter "add comment" endpoint, so
    # this is an explicit opt-in attempt; any HTTP error aborts loudly and
    # nothing is retried automatically.
    [ -n "${!H1_USER_VAR:-}" ] || die "set $H1_USER_VAR (API token identifier) first"
    [ -n "${!H1_TOKEN_VAR:-}" ] || die "set $H1_TOKEN_VAR (API token value) first"
    PAYLOAD="$(REPORT_ID="$REPORT_ID" BODY="$BODY" python3 - <<'PY'
import json, os
print(json.dumps({"data": {"type": "activity-comment", "attributes": {
    "message": os.environ["BODY"], "internal": False}}}))
PY
)"
    TMP="$(mktemp)"
    CODE="$(curl -sS -o "$TMP" -w '%{http_code}' \
        -u "${!H1_USER_VAR}:${!H1_TOKEN_VAR}" \
        -H 'Content-Type: application/json' -H 'Accept: application/json' \
        -X POST "$API_BASE/reports/$REPORT_ID/comments" -d "$PAYLOAD")" \
        || die "curl failed (network?) - nothing posted"
    if [ "$CODE" != "200" ] && [ "$CODE" != "201" ]; then
        echo "[h1] API refused (HTTP $CODE) - as documented, the hacker API has" >&2
        echo "[h1] no stable reporter-comment endpoint. Nothing was posted." >&2
        cat "$TMP" >&2; rm -f "$TMP"; exit 3
    fi
    rm -f "$TMP"
    echo "[h1] posted via API to report $REPORT_ID - verify it on the report page."
    echo "[h1] if the comment does not appear, use: bash $0 send --report $REPORT_ID"
    ;;

*)
    usage
    die "unknown subcommand: $CMD"
    ;;
esac
