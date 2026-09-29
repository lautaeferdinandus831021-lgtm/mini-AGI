"""The report-knowledge store: every bounty report, kept as a record.

The security work this repo ships (curl UAF H1 #3971462, the crypto.com
negative assessment, the skills-gate decision table) produced real reports
whose details lived in evidence directories and one linear index file. That
does not scale past a handful of findings, and nothing could ANSWER questions
- "what did we conclude about target X", "what is still open", "what did the
2026-09-28 retest change". This module is the answer: one JSON record per
report, written atomically, queryable by keyword / status / target, and
renderable back to the markdown a triager reads.

A record is the unit of recall, and it carries everything a cold reader needs:

    id          short unique slug ("curl-referer-uaf") - the filename
    title       one line, human
    program     which bounty program / target the report went to
    target      the tested surface (host, component, package)
    report_type verification | submission | negative-result | internal
    status      draft | submitted | informative | accepted | duplicate |
                resolved | n/a-informational | withdrawn
    severity    the claimed/assigned severity, or "none"
    cwe         ["CWE-416", ...]
    date_filed, date_closed   ISO dates, either may be empty
    timeline    [{"date", "event"}...] - the facts, in order
    key_facts   the load-bearing conclusions, one string each
    evidence    [{"path", "note"}...] - where the raw proof lives
    commands    how to regenerate the evidence
    lessons     what the process taught (the part worth keeping forever)
    references  links / ticket ids
    related     ids of other records in this store

Rules the store enforces:
  * writes are atomic (tmp + rename, the store.py discipline) - a crash
    mid-write leaves the previous record intact, never a truncated one;
  * unknown status / report_type values are rejected at save time, so the
    enum a query filters on cannot silently drift;
  * ids are validated slugs, and saving never overwrites silently - pass
    overwrite=True to replace an existing record on purpose.

Storage is one JSON file per record under knowledge/ (gitignored evidence
stays where it is; the record POINTS at it). CLI:

    python3 -m minagi.knowledge list [PATTERN] [--status S] [--target T]
    python3 -m minagi.knowledge show ID [--markdown]
    python3 -m minagi.knowledge search WORD [WORD...] [--status S]
    python3 -m minagi.knowledge add FILE.json [--overwrite]
    python3 -m minagi.knowledge stats
    python3 -m minagi.knowledge timeline [--status S]
"""

import json
import os
import re
import sys

KNOWLEDGE_DIR = os.environ.get("KNOWLEDGE_DIR", "knowledge")

STATUSES = ("draft", "submitted", "informative", "accepted", "duplicate",
            "resolved", "n/a-informational", "withdrawn")
REPORT_TYPES = ("verification", "submission", "negative-result", "internal")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")

_LIST_FIELDS = ("cwe", "timeline", "key_facts", "evidence", "commands",
                "lessons", "references", "related")
_STR_FIELDS = ("id", "title", "program", "target", "report_type", "status",
               "severity", "date_filed", "date_closed", "summary")


class RecordError(ValueError):
    """A record that would not round-trip or would not be findable."""


# ----------------------------------------------------------------- validation
def validate(rec):
    """Raise RecordError unless `rec` is a well-formed knowledge record.

    Anything a query or a renderer relies on is checked here rather than
    forgiven at read time: a record that sorts wrongly or renders half a
    report is worse than one that refuses to be saved.
    """
    if not isinstance(rec, dict):
        raise RecordError("a record must be a JSON object")
    missing = [f for f in _STR_FIELDS if f not in rec]
    if missing:
        raise RecordError("missing required field(s): " + ", ".join(missing))
    if not isinstance(rec.get("id"), str) or not _SLUG_RE.match(rec["id"]):
        raise RecordError(f"id must match {_SLUG_RE.pattern!r} (got "
                          f"{rec.get('id')!r})")
    for f in _STR_FIELDS:
        if not isinstance(rec[f], str):
            raise RecordError(f"{f} must be a string (got {type(rec[f]).__name__})")
    if not rec["title"].strip():
        raise RecordError("title must not be empty")
    if rec["report_type"] not in REPORT_TYPES:
        raise RecordError(f"report_type must be one of {REPORT_TYPES}")
    if rec["status"] not in STATUSES:
        raise RecordError(f"status must be one of {STATUSES}")
    for f in ("date_filed", "date_closed"):
        if rec[f] and not _DATE_RE.match(rec[f]):
            raise RecordError(f"{f} must be YYYY-MM-DD or empty (got {rec[f]!r})")
    for f in _LIST_FIELDS:
        if not isinstance(rec.get(f), list):
            raise RecordError(f"{f} must be a list (got {type(rec.get(f)).__name__})")
    for t in rec.get("timeline", []):
        if not (isinstance(t, dict) and isinstance(t.get("date"), str)
                and _DATE_RE.match(t.get("date", "")) and isinstance(t.get("event"), str)):
            raise RecordError("timeline entries must be {date: YYYY-MM-DD, event}")
    for e in rec.get("evidence", []):
        if not (isinstance(e, dict) and e.get("path")):
            raise RecordError("evidence entries must be {path, note}")
    return rec


# --------------------------------------------------------------------- store
def _path(rid):
    return os.path.join(KNOWLEDGE_DIR, rid + ".json")


def save(rec, overwrite=False):
    """Validate and atomically write one record. Returns the record."""
    validate(rec)
    path = _path(rec["id"])
    if os.path.exists(path) and not overwrite:
        raise RecordError(f"{rec['id']} already exists; pass overwrite=True "
                          f"to replace it on purpose")
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)
    return rec


def load(rid):
    """One record by id. FileNotFoundError when the id is unknown."""
    with open(_path(rid)) as f:
        return validate(json.load(f))


def exists(rid):
    return os.path.exists(_path(rid))


def _iter_paths():
    if not os.path.isdir(KNOWLEDGE_DIR):
        return
    for name in sorted(os.listdir(KNOWLEDGE_DIR)):
        if name.endswith(".json") and not name.endswith(".tmp"):
            yield os.path.join(KNOWLEDGE_DIR, name)


def list_records(status=None, target=None):
    """Every record, sorted by date_filed (undated last), then id."""
    out = []
    for path in _iter_paths():
        try:
            rec = load(os.path.basename(path)[:-5])
        except (RecordError, json.JSONDecodeError):
            continue            # a broken record is skipped, never fatal
        if status and rec["status"] != status:
            continue
        if target and target.lower() not in (rec["target"] + " " + rec["program"]).lower():
            continue
        out.append(rec)
    out.sort(key=lambda r: (r["date_filed"] or "9999-99-99", r["id"]))
    return out


def search(words, status=None):
    """Records whose full text contains EVERY word (case-insensitive).

    The point is recall, not ranking: bounty questions are conjunctive
    ("which curl + referer work did we do"). Words match anywhere in the
    record - title, facts, timeline events, evidence notes, lessons.
    """
    words = [w.lower() for w in words if w]
    out = []
    for rec in list_records(status=status):
        hay = json.dumps(rec, sort_keys=True).lower()
        if all(w in hay for w in words):
            out.append(rec)
    return out


def timeline(status=None):
    """Every timeline entry across records, newest first, tagged by id."""
    events = []
    for rec in list_records(status=status):
        for t in rec.get("timeline", []):
            events.append({"id": rec["id"], "date": t["date"],
                           "event": t["event"]})
    events.sort(key=lambda e: e["date"], reverse=True)
    return events


def stats():
    """Store-level counters - the 'where do we stand' one-liner."""
    records = list_records()
    by_status = {}
    for r in records:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    return {"records": len(records), "by_status": by_status,
            "targets": sorted({r["target"] for r in records})}


# ------------------------------------------------------------------ rendering
def to_markdown(rec):
    """The triager-readable report. Pure function of the record."""
    L = [f"# {rec['title']}", ""]
    meta = [(k, rec[k]) for k in ("program", "target", "report_type", "status",
                                  "severity", "date_filed", "date_closed")]
    L.append("| field | value |")
    L.append("|---|---|")
    for k, v in meta:
        if v:
            L.append(f"| {k} | {v} |")
    if rec.get("cwe"):
        L.append(f"| cwe | {', '.join(rec['cwe'])} |")
    L.append("")
    if rec.get("summary"):
        L += [rec["summary"], ""]
    if rec.get("key_facts"):
        L += ["## Key facts", ""]
        L += [f"- {f}" for f in rec["key_facts"]] + [""]
    if rec.get("timeline"):
        L += ["## Timeline", "", "| date | event |", "|---|---|"]
        L += [f"| {t['date']} | {t['event']} |" for t in rec["timeline"]]
        L.append("")
    if rec.get("evidence"):
        L += ["## Evidence", ""]
        L += [f"- `{e['path']}`" + (f" - {e['note']}" if e.get("note") else "")
              for e in rec["evidence"]] + [""]
    if rec.get("commands"):
        L += ["## Reproduce", ""]
        L += [f"```bash\n{c}\n```" for c in rec["commands"]] + [""]
    if rec.get("lessons"):
        L += ["## Lessons", ""]
        L += [f"- {x}" for x in rec["lessons"]] + [""]
    if rec.get("references"):
        L += ["## References", ""]
        L += [f"- {r}" for r in rec["references"]] + [""]
    if rec.get("related"):
        L += ["## Related records", "",
              ", ".join(f"`{x}`" for x in rec["related"]), ""]
    return "\n".join(L).rstrip() + "\n"


# ------------------------------------------------------------------------ CLI
def _fmt_status(s):
    return {"informative": "informative (closed)",
            "n/a-informational": "n/a (informational)"}.get(s, s)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = __doc__.split("CLI:")[1].split('"""')[0].strip()
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(usage)
        return 0
    cmd, rest = argv[0], argv[1:]

    if cmd == "list":
        status = None
        target = None
        if "--status" in rest:
            i = rest.index("--status")
            status = rest[i + 1]
            del rest[i:i + 2]
        if "--target" in rest:
            i = rest.index("--target")
            target = rest[i + 1]
            del rest[i:i + 2]
        recs = list_records(status=status, target=target)
        if rest:                                # optional id substring filter
            recs = [r for r in recs if rest[0].lower() in r["id"].lower()]
        if not recs:
            print("no records" + (f" matching {rest}" if rest else ""))
            return 0
        for r in recs:
            print(f"{r['id']:<28} {r['status']:<19} {r['date_filed'] or '-':<10} "
                  f"{r['title']}")
        return 0

    if cmd == "show":
        if not rest:
            print("usage: show ID [--markdown]", file=sys.stderr)
            return 2
        rec = load(rest[0])
        if "--markdown" in rest:
            print(to_markdown(rec))
        else:
            print(json.dumps(rec, indent=2, sort_keys=True))
        return 0

    if cmd == "search":
        status = None
        if "--status" in rest:
            i = rest.index("--status")
            status = rest[i + 1]
            del rest[i:i + 2]
        recs = search(rest, status=status)
        if not recs:
            print("no records match", rest)
            return 0
        for r in recs:
            print(f"{r['id']:<28} {_fmt_status(r['status']):<24} {r['title']}")
        return 0

    if cmd == "add":
        if not rest:
            print("usage: add FILE.json [--overwrite]", file=sys.stderr)
            return 2
        with open(rest[0]) as f:
            rec = json.load(f)
        save(rec, overwrite="--overwrite" in rest)
        print(f"saved knowledge/{rec['id']}.json")
        return 0

    if cmd == "stats":
        s = stats()
        print(f"{s['records']} records")
        for k in sorted(s["by_status"]):
            print(f"  {k:<19} {s['by_status'][k]}")
        print("targets: " + ", ".join(s["targets"]))
        return 0

    if cmd == "timeline":
        status = None
        if "--status" in rest:
            i = rest.index("--status")
            status = rest[i + 1]
            del rest[i:i + 2]
        for e in timeline(status=status):
            print(f"{e['date']}  [{e['id']}]  {e['event']}")
        return 0

    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
