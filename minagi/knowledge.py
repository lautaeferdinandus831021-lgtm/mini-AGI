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
stays where it is; the record POINTS at it).

The testing scope - which targets / programs this workspace is working - is
DYNAMIC, not a list hardcoded anywhere in the code: it lives in
knowledge/scope.json, grows when a record names a target the scope has
never seen, and is editable on purpose (scope-add / scope-remove). The code
only defines the SHAPE of a scope entry:

    {"target": "paypal.com", "program": "HackerOne (paypal)",
     "added": "2026-09-30", "note": "why this is in scope",
     "status": "active"}

`scope_targets()` answers "what are we watching" - the union of the declared
scope, sorted, oldest first. Editing the file (or using the CLI) changes
what every future list/search/stats command reports as the scope; nothing
is baked in at import time. CLI:

    python3 -m minagi.knowledge list [PATTERN] [--status S] [--target T]
    python3 -m minagi.knowledge show ID [--markdown]
    python3 -m minagi.knowledge search WORD [WORD...] [--status S]
    python3 -m minagi.knowledge add FILE.json [--overwrite]
    python3 -m minagi.knowledge stats
    python3 -m minagi.knowledge timeline [--status S]
    python3 -m minagi.knowledge scope            # the active scope
    python3 -m minagi.knowledge scope-add TARGET [--program P] [--note N]
    python3 -m minagi.knowledge scope-remove TARGET
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
            "targets": sorted({r["target"] for r in records}),
            "scope": scope_targets()}


# ------------------------------------------------------------- dynamic scope
# The scope lives in the store, not in the code: one JSON file of entries
# {target, program, added, note, status}. Growing it when a record names a
# new target, or editing it with the CLI, changes what "scope" means from
# then on - nothing is a hardcoded list.

class ScopeError(ValueError):
    """A scope entry that would not round-trip or would not be answerable."""


_SCOPE_REQUIRED = ("target", "program", "added", "status")
_SCOPE_STATUSES = ("active", "monitor", "retired", "out-of-scope")


def scope_path():
    """Where the scope file lives: inside the store, so one KNOWLEDGE_DIR
    carries its records AND its scope."""
    return os.path.join(KNOWLEDGE_DIR, "scope.json")


def load_scope():
    """The declared scope as a list of entries, oldest first.

    Reads the file on EVERY call - the scope is meant to be edited while
    the app runs. A missing file is an empty scope, not an error; a
    malformed one is skipped wholesale and reported as empty, never fatal
    to the store, and an entry that fails validation is dropped rather
    than allowed to break every query that lists the scope.
    """
    try:
        with open(scope_path()) as f:
            entries = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(entries, list):
        return []
    out = []
    for e in entries:
        try:
            out.append(validate_scope_entry(e))
        except ScopeError:
            continue
    out.sort(key=lambda e: (e["added"] or "9999-99-99", e["target"]))
    return out


def validate_scope_entry(entry):
    """Raise ScopeError unless `entry` is a well-formed scope entry."""
    if not isinstance(entry, dict):
        raise ScopeError("a scope entry must be a JSON object")
    missing = [k for k in _SCOPE_REQUIRED if k not in entry]
    if missing:
        raise ScopeError("missing scope field(s): " + ", ".join(missing))
    for k in _SCOPE_REQUIRED + ("note",):
        if k in entry and not isinstance(entry[k], str):
            raise ScopeError(f"scope {k} must be a string")
    if not entry["target"].strip():
        raise ScopeError("scope target must not be empty")
    if entry["added"] and not _DATE_RE.match(entry["added"]):
        raise ScopeError(f"scope added must be YYYY-MM-DD (got "
                         f"{entry['added']!r})")
    if entry["status"] not in _SCOPE_STATUSES:
        raise ScopeError(f"scope status must be one of {_SCOPE_STATUSES}")
    return {"target": entry["target"], "program": entry["program"],
            "added": entry["added"], "status": entry["status"],
            "note": entry.get("note", "")}


def save_scope(entries):
    """Atomically replace the whole scope file. Validates every entry and
    rejects duplicate targets - two entries for one target is how a scope
    stops meaning anything."""
    entries = [validate_scope_entry(e) for e in entries]
    targets = [e["target"] for e in entries]
    if len(targets) != len(set(targets)):
        raise ScopeError("duplicate target in scope")
    entries.sort(key=lambda e: (e["added"] or "9999-99-99", e["target"]))
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
    tmp = scope_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(entries, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, scope_path())
    return entries


def scope_add(target, program="", note="", status="active", added=""):
    """Add one target to the scope. program/note default to sensible
    strings so a quick scope-add stays one argument. Raises ScopeError if
    the target is already declared - use scope_status() to change it."""
    target = target.strip()
    if not target:
        raise ScopeError("target must not be empty")
    entries = load_scope()
    if any(e["target"] == target for e in entries):
        raise ScopeError(f"{target!r} is already in scope - use "
                         f"scope_status() to change it")
    entry = {"target": target,
             "program": program or "unspecified",
             "added": added or _today(),
             "status": status,
             "note": note}
    entries.append(entry)
    save_scope(entries)
    return entry


def scope_remove(target):
    """Drop one target from the scope. ScopeError when it is not there -
    removing nothing silently would hide the typo that called for it."""
    entries = load_scope()
    kept = [e for e in entries if e["target"] != target]
    if len(kept) == len(entries):
        raise ScopeError(f"{target!r} is not in scope - current: "
                         f"{[e['target'] for e in entries] or 'none'}")
    save_scope(kept)


def scope_status(target, status):
    """Flip one target's status (active / monitor / retired /
    out-of-scope) without touching the rest."""
    if status not in _SCOPE_STATUSES:
        raise ScopeError(f"scope status must be one of {_SCOPE_STATUSES}")
    entries = load_scope()
    for e in entries:
        if e["target"] == target:
            e["status"] = status
            save_scope(entries)
            return e
    raise ScopeError(f"{target!r} is not in scope")


def scope_targets():
    """The scope, flattened to the sorted target strings - the one-line
    answer to 'what are we watching right now'."""
    return [e["target"] for e in load_scope()]


def _today():
    import datetime
    return datetime.date.today().isoformat()


def _grow_scope(rec):
    """Add a record's target to the scope when it is new.

    save() calls this so the scope keeps pace with the work: the first
    record about a target declares it, dynamically, without anyone editing
    a config. A scope file that cannot be written must not fail the
    record's save - the scope is a convenience grown FROM the records, not
    a constraint they answer to - so every failure here is swallowed.
    """
    try:
        entries = load_scope()
        if any(e["target"] == rec["target"] for e in entries):
            return
        entries.append({"target": rec["target"],
                        "program": rec["program"],
                        "added": rec["date_filed"] or _today(),
                        "status": "active",
                        "note": "grown automatically from record "
                                + rec["id"]})
        save_scope(entries)
    except Exception:                                  # noqa: BLE001
        pass


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
    _grow_scope(rec)
    return rec


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
        print("targets: " + (", ".join(s["targets"]) or "none"))
        print("scope:   " + (", ".join(s["scope"]) or "empty"))
        return 0

    if cmd == "scope":
        for e in load_scope():
            print(f"{e['target']:<42} {e['status']:<12} "
                  f"{e['added'] or '-':<10} {e['program']}")
        if not load_scope():
            print("(empty scope - save a record or run scope-add to start it)")
        return 0

    if cmd in ("scope-add", "scope-remove", "scope-status"):
        try:
            if cmd == "scope-add":
                if not rest:
                    print("usage: scope-add TARGET [--program P] [--note N] "
                          "[--status S]", file=sys.stderr)
                    return 2
                opts = dict(zip(rest[1::2], rest[2::2]))
                for flag in opts:
                    if flag not in ("--program", "--note", "--status"):
                        raise ScopeError(f"unknown flag {flag}")
                entry = scope_add(
                    rest[0], program=opts.get("--program", ""),
                    note=opts.get("--note", ""),
                    status=opts.get("--status", "active"))
                print(f"scope: +{entry['target']} ({entry['status']}, "
                      f"added {entry['added']})")
            elif cmd == "scope-remove":
                if not rest:
                    print("usage: scope-remove TARGET", file=sys.stderr)
                    return 2
                scope_remove(rest[0])
                print(f"scope: -{rest[0]}")
            else:
                if len(rest) < 2:
                    print("usage: scope-status TARGET STATUS", file=sys.stderr)
                    return 2
                scope_status(rest[0], rest[1])
                print(f"scope: {rest[0]} -> {rest[1]}")
        except ScopeError as exc:
            print(f"[scope] {exc}", file=sys.stderr)
            return 2
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
