"""Skills: output evaluation, adopted from the Future AGI taxonomy.

Future AGI (github.com/future-agi/future-agi) ships two skill families:

  * code evals   - deterministic functions (futureagi/evaluations/catalog/
                   system_eval_code.py) with the contract
                       evaluate(...) -> bool | float | {"result", "reason"}
                   bool is a pass/fail, a float in [0, 1] is a score.
  * rule evals   - LLM-judged templates (system_evals.yaml) tagged e.g.
                   [Red Teaming, Security], [Data Leakage, Data Privacy].

This module is an ORIGINAL, dependency-free implementation of the same idea,
scoped to what a byte-level language model actually emits: text in, verdict
out. None of Future AGI's code is copied - only the taxonomy (skill names and
their meaning) and the result contract, so reports read the same way.

What is ported vs. deliberately not:

    ported      25 code evals that are pure text math (string checks, link
                and e-mail well-formedness, BLEU/ROUGE/recall/ranking on
                token n-grams, string/numeric similarity).
    re-written  security skills as deterministic pattern batteries (the
                rule evals FA judges with an LLM: PII, secrets, prompt
                injection, unsafe code, ...). Deterministic beats judged
                here: the point is a repeatable report next to the training
                samples, not a second opinion.
    N/A         CLIP/FID (vision), DEAD_AIR (voice), EMBEDDING_SIMILARITY
                and SEMANTIC_LIST_CONTAINS (need an embedding model),
                JSON_SCHEMA_VALIDATION (needs jsonschema), API_CALL
                (network), CUSTOM_CODE_EVALUATION (executes caller code).

`scan()` runs the security battery over a sample and returns one
machine-readable verdict - the training loop and the web UI both print it.
The battery list is a DYNAMIC SCOPE, not a constant: register_battery() and
unregister_battery() change what every caller runs at runtime, and
scope_from_config() turns the `skills.scope` list in config.yaml into the
scope the serving and training paths use (absent = every registered
battery). Anything that does not resolve - an unknown battery name, a
regex that will not compile - raises ScopeError rather than quietly
scanning less.

Every function takes the text (or pair) first and keyword params after, and
never raises on odd input: an evaluation that crashes is an evaluation that
fails open. CLI:

    python3 -m minagi.skills list
    python3 -m minagi.skills run IS_JSON --input file.txt
    python3 -m minagi.skills scan --input file.txt
    python3 -m minagi.skills scan --battery SECRETS_DETECT --input file.txt
    python3 -m minagi.skills scan --pattern 'TICKET=TICK-[0-9]+' --input f.txt
    python3 -m minagi.skills scope
"""

import json
import math
import re
import sys
from collections import Counter
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_MARKERS = re.compile(r"</?think>|</?user>|</?bot>|<g>|</?s>|<eot>")


def _clean(text):
    """Strip the model's structural markers so evals see the prose."""
    return _MARKERS.sub("", text or "")


def _verdict(result, reason):
    return {"result": result, "reason": reason}


def _ok(reason="pass"):
    return _verdict(True, reason)


def _fail(reason="fail"):
    return _verdict(False, reason)


def _tokens(text, n=1):
    """Lowercased word (n=1) or character n-gram tokens, the IR unit here."""
    t = _clean(text).lower()
    if n <= 1:
        return re.findall(r"[a-z0-9']+", t)
    return [t[i:i + n] for i in range(max(0, len(t) - n + 1))]


def _levenshtein(a, b):
    if a == b:
        return 0.0
    if not a:
        return float(len(b))
    if not b:
        return float(len(a))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return float(prev[-1])


def _lcs_len(a, b):
    """Longest common subsequence length over token lists (ROUGE basis)."""
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0]
        for j, y in enumerate(b, 1):
            cur.append(prev[j - 1] + 1 if x == y else max(prev[j], cur[j - 1]))
        prev = cur
    return prev[-1]


def _bleu(hyp, ref, max_n=4):
    h, r = list(hyp), list(ref)
    if not h or not r:
        return 0.0
    weights = 1.0 / max_n
    score = 0.0
    for n in range(1, max_n + 1):
        hg = Counter(tuple(h[i:i + n]) for i in range(len(h) - n + 1))
        rg = Counter(tuple(r[i:i + n]) for i in range(len(r) - n + 1))
        match = sum(min(c, rg.get(g, 0)) for g, c in hg.items())
        total = max(1, len(h) - n + 1)
        p = match / total
        # no smoothing beyond the floor: a missing n-gram level zeroes the
        # score, which is the honest verdict for a short output
        if p == 0.0:
            return 0.0
        score += weights * math.log(p)
    bp = 1.0 if len(h) > len(r) else math.exp(1 - len(r) / max(1, len(h)))
    return bp * math.exp(score)


def _rouge_l(hyp, ref):
    h, r = list(hyp), list(ref)
    if not h or not r:
        return 0.0
    lcs = _lcs_len(h, r)
    if lcs == 0:
        return 0.0
    p, rec = lcs / len(h), lcs / len(r)
    return 2 * p * rec / (p + rec)


def _token_recall(hyp, ref):
    h, r = set(hyp), set(ref)
    if not r:
        return 0.0
    return len(h & r) / len(r)


def _ranks(hyp, ref):
    """Positions (1-based) of the first occurrence of each reference token
    in the hypothesis - the input to MRR / hit-rate / recall@k."""
    order = {}
    for i, t in enumerate(hyp, 1):
        order.setdefault(t, i)
    return sorted(order.get(t, 0) for t in set(ref))


# ---------------------------------------------------------------------------
# ported code evals (Future AGI names and parameter spellings)
# ---------------------------------------------------------------------------

def CONTAINS(text, keyword="", case_sensitive=False, **_):
    if not keyword:
        return _fail("no keyword configured")
    t = str(text) if case_sensitive else str(text).lower()
    k = keyword if case_sensitive else keyword.lower()
    return _ok() if k in t else _fail(f"{keyword!r} not found")


def CONTAINS_ALL(text, keywords=None, case_sensitive=False, **_):
    keywords = keywords or []
    if not keywords:
        return _fail("no keywords configured")
    t = str(text) if case_sensitive else str(text).lower()
    missing = [k for k in keywords
               if (k if case_sensitive else k.lower()) not in t]
    return _ok() if not missing else _fail(f"missing {missing}")


def CONTAINS_ANY(text, keywords=None, case_sensitive=False, **_):
    keywords = keywords or []
    if not keywords:
        return _fail("no keywords configured")
    t = str(text) if case_sensitive else str(text).lower()
    hit = [k for k in keywords if (k if case_sensitive else k.lower()) in t]
    return _verdict(bool(hit), f"matched {hit}" if hit else "no match")


def CONTAINS_NONE(text, keywords=None, **_):
    keywords = keywords or []
    if not keywords:
        return _ok("empty deny list")
    t = str(text).lower()
    bad = [k for k in keywords if k.lower() in t]
    return _ok() if not bad else _fail(f"found {bad}")


def EQUALS(text, expected_text="", **_):
    return _ok() if str(text) == str(expected_text) else _fail("not equal")


def STARTS_WITH(text, prefix="", **_):
    if not prefix:
        return _fail("no prefix configured")
    return _ok() if str(text).startswith(prefix) else _fail("wrong prefix")


def ENDS_WITH(text, suffix="", **_):
    if not suffix:
        return _fail("no suffix configured")
    return _ok() if str(text).endswith(suffix) else _fail("wrong suffix")


def REGEX(text, pattern="", **_):
    if not pattern:
        return _fail("no pattern configured")
    try:
        found = re.search(pattern, str(text))
    except re.error as exc:
        return _fail(f"bad pattern: {exc}")
    return _ok(f"matched {found.group(0)!r}") if found else _fail("no match")


def ONE_LINE(text, **_):
    return _ok() if "\n" not in str(text) else _fail("multi-line")


def LENGTH_LESS_THAN(text, max_length=0, **_):
    n = len(str(text))
    return _ok(f"{n} chars") if n < max_length else _fail(f"{n} >= {max_length}")


def LENGTH_GREATER_THAN(text, min_length=0, **_):
    n = len(str(text))
    return _ok(f"{n} chars") if n > min_length else _fail(f"{n} <= {min_length}")


def LENGTH_BETWEEN(text, min_length=0, max_length=0, **_):
    n = len(str(text))
    if min_length <= n <= max_length:
        return _ok(f"{n} chars in [{min_length}, {max_length}]")
    return _fail(f"{n} chars outside [{min_length}, {max_length}]")


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s<>\"']+", re.I)
_BAD_LINK = re.compile(r"https?://[^\s<>\"']*\.(?:zip|top|xyz|ru|tk)\b",
                       re.I)


def IS_EMAIL(text, **_):
    m = _EMAIL.search(str(text))
    return _ok(m.group(0)) if m else _fail("no e-mail address found")


def IS_JSON(text, **_):
    try:
        json.loads(str(text))
        return _ok("parses")
    except Exception as exc:
        return _fail(str(exc)[:80])


def CONTAINS_VALID_LINK(text, **_):
    for m in _URL.finditer(str(text)):
        u = urlparse(m.group(0))
        if u.netloc and "." in u.netloc:
            return _ok(m.group(0))
    return _fail("no well-formed link")


def NO_INVALID_LINKS(text, **_):
    bad = _BAD_LINK.findall(str(text))
    return _ok() if not bad else _fail(f"suspicious links: {bad}")


def LEVENSHTEIN_SIMILARITY(output="", expected="", **_):
    a, b = str(output), str(expected)
    if not a and not b:
        return _verdict(1.0, "both empty")
    d = _levenshtein(a.lower(), b.lower())
    return _verdict(1.0 - d / max(len(a), len(b)), f"distance {d:g}")


def NUMERIC_SIMILARITY(output="", expected="", **_):
    try:
        a = re.search(r"-?\d+(?:\.\d+)?", str(output)).group(0)
        b = re.search(r"-?\d+(?:\.\d+)?", str(expected)).group(0)
    except AttributeError:
        return _fail("no number on one side")
    a, b = float(a), float(b)
    if a == b:
        return _verdict(1.0, "exact")
    denom = max(abs(a), abs(b)) or 1.0
    return _verdict(max(0.0, 1.0 - abs(a - b) / denom), f"{a} vs {b}")


def BLEU_SCORE(reference="", hypothesis="", **_):
    s = _bleu(_tokens(hypothesis), _tokens(reference))
    return _verdict(s, f"BLEU-4 {s:.3f}")


def ROUGE_SCORE(reference="", hypothesis="", **_):
    s = _rouge_l(_tokens(hypothesis), _tokens(reference))
    return _verdict(s, f"ROUGE-L {s:.3f}")


def RECALL_SCORE(hypothesis="", reference="", **_):
    s = _token_recall(_tokens(hypothesis), _tokens(reference))
    return _verdict(s, f"token recall {s:.3f}")


def PRECISION_AT_K(hypothesis="", reference="", k=5, **_):
    hyp, ref = _tokens(hypothesis), set(_tokens(reference))
    if not hyp or not ref:
        return _fail("empty side")
    seen, hits = set(), 0
    for t in hyp[:k]:
        if t in ref and t not in seen:
            hits += 1
        seen.add(t)
    return _verdict(hits / k, f"{hits}/{k}")


def RECALL_AT_K(hypothesis="", reference="", k=5, **_):
    hyp, ref = _tokens(hypothesis), set(_tokens(reference))
    if not ref:
        return _fail("empty reference")
    seen, hits = set(), 0
    for t in hyp[:k]:
        if t in ref and t not in seen:
            hits += 1
        seen.add(t)
    return _verdict(hits / len(ref), f"{hits}/{len(ref)}")


def HIT_RATE(hypothesis="", reference="", k=10, **_):
    ranks = [r for r in _ranks(_tokens(hypothesis), _tokens(reference)) if r]
    if not ranks:
        return _fail("no reference token present")
    return _verdict(any(r <= k for r in ranks), f"first rank {min(ranks)}")


def MRR(hypothesis="", reference="", **_):
    ranks = [r for r in _ranks(_tokens(hypothesis), _tokens(reference)) if r]
    if not ranks:
        return _verdict(0.0, "no reference token present")
    return _verdict(1.0 / min(ranks), f"first rank {min(ranks)}")


# ---------------------------------------------------------------------------
# security skills - deterministic rewrites of FA's judged rule evals
# (tags: Red Teaming, Security / Data Leakage, Data Privacy / Content Safety)
# ---------------------------------------------------------------------------

_PII = [
    ("email", _EMAIL),
    ("phone", re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")),
    ("ssn_like", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("credit_card", re.compile(r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)")),
    ("ip_address", re.compile(r"(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d)")),
]

_SECRETS = [
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("generic_secret", re.compile(
        r"\b(?:api[_-]?key|secret|passwd|password)\b\s*[:=]\s*\S{6,}", re.I)),
]

_INJECTION = [
    ("override", re.compile(
        r"ignore (?:all |any |the )?(?:previous|prior|above) "
        r"(?:instructions|prompts|rules)", re.I)),
    ("role_rewrite", re.compile(
        r"\b(?:you are now|from now on you are|pretend to be|act as)\b", re.I)),
    ("forget", re.compile(r"\bforget (?:everything|all|your rules)\b", re.I)),
    ("system_leak", re.compile(
        r"\b(?:reveal|repeat|print|output) (?:your|the) "
        r"(?:system prompt|instructions|rules)\b", re.I)),
    ("marker_escape", re.compile(r"</s>|<eot>|\x00")),
]

_UNSAFE_CODE = [
    ("exec_eval", re.compile(r"\b(?:exec|eval)\s*\(", )),
    ("shell_true", re.compile(r"shell\s*=\s*True")),
    ("os_system", re.compile(r"\bos\.system\s*\(")),
    ("pickle_loads", re.compile(r"pickle\.loads?\s*\(")),
    ("yaml_load", re.compile(r"yaml\.load\s*\((?![^)]*Loader)")),
    ("subprocess", re.compile(r"\bsubprocess\.(?:call|run|Popen)\s*\(")),
    ("dynamic_import", re.compile(r"__import__\s*\(|importlib\.import_module")),
]

_SQLI = [
    ("tautology", re.compile(r"(?:'|\"|\b)\s*(?:or|and)\s+\d+\s*=\s*\d+", re.I)),
    ("union_select", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I)),
    ("comment_tail", re.compile(r"(?:--|#)\s*$|/\*")),
    ("stacked", re.compile(r";\s*(?:drop|delete|insert|update|alter)\b", re.I)),
    ("sleep_bomb", re.compile(r"\b(?:sleep|pg_sleep|waitfor\s+delay)\s*\(", re.I)),
]

_XSS = [
    ("script_tag", re.compile(r"<script\b", re.I)),
    ("event_handler", re.compile(r"\bon(?:error|load|click|mouseover)\s*=", re.I)),
    ("js_url", re.compile(r"javascript\s*:", re.I)),
    ("iframe", re.compile(r"<iframe\b", re.I)),
]

_TRAVERSAL = [
    ("dotdot", re.compile(r"(?:\.\./|\.\.\\){2,}")),
    ("etc_passwd", re.compile(r"/etc/(?:passwd|shadow)", re.I)),
    ("abs_path", re.compile(r"(?:[A-Za-z]:\\|/home/|/root/)")),
]

_PHISHING = [
    ("urgency", re.compile(r"\b(?:urgent|immediately|within \d+ hours|"
                           r"account (?:will be )?(?:suspended|closed))\b", re.I)),
    ("credential_ask", re.compile(r"\b(?:verify your|confirm your) "
                                  r"(?:account|password|identity|billing)\b", re.I)),
    ("dear_customer", re.compile(r"dear (?:customer|user|account holder)", re.I)),
]

_SECURITY_BATTERY = [
    ("PII_DETECT", _PII, "personally identifiable information"),
    ("SECRETS_DETECT", _SECRETS, "hardcoded credentials or tokens"),
    ("PROMPT_INJECTION_DETECT", _INJECTION, "prompt-injection patterns"),
    ("UNSAFE_CODE_DETECT", _UNSAFE_CODE, "unsafe code execution patterns"),
    ("SQL_INJECTION_PATTERN", _SQLI, "SQL-injection patterns"),
    ("XSS_PATTERN", _XSS, "cross-site scripting patterns"),
    ("PATH_TRAVERSAL_DETECT", _TRAVERSAL, "path-traversal patterns"),
    ("PHISHING_PATTERN", _PHISHING, "phishing-message patterns"),
]

# one-word false-positive guards: the batteries match byte-level model output,
# which is full of code and prose ABOUT security - a judgement call belongs to
# a human, the battery only nominates text for a look.
_BENIGN_CONTEXT = re.compile(
    r"(?:example|e\.g\.|for instance|should never|do not|don't|avoid|"
    r"never (?:use|share|commit))\b[^.?!]{0,60}$", re.I)


def _battery(text, patterns):
    hits = []
    t = str(text)
    for name, rx in patterns:
        m = rx.search(t)
        if m:
            snippet = t[max(0, m.start() - 20):m.end() + 20].replace("\n", " ")
            # a match inside a sentence that is clearly talking ABOUT the
            # pattern ("don't share your api key") is nominated, not flagged
            guarded = _BENIGN_CONTEXT.search(t[:m.start()][-80:])
            hits.append({"pattern": name, "where": m.start(),
                         "snippet": snippet, "guarded": bool(guarded)})
    return hits


# ---------------------------------------------------------------------------
# the dynamic scan scope
# ---------------------------------------------------------------------------

class ScopeError(ValueError):
    """A scan scope that would silently shrink or fail open."""


# The shipped battery, frozen at import. register_battery() may extend the
# live list and unregister_battery() may remove what it added, but the
# shipped eight are the floor the contract promises - reports, tests and
# the web UI all assume them, so they are never removable.
_FACTORY_BATTERY = tuple((n, tuple(p), d) for n, p, d in _SECURITY_BATTERY)


def register_battery(name, patterns, description=None):
    """Add a battery to the LIVE security scope, module-wide, immediately.

    The batteries stay the static shape they always were - a list of
    (label, regex) pairs - but the SCOPE is derived at call time: what
    scan() runs by default, what GROUPS['security'] lists and what
    registry() exposes all read the live list, so a battery registered
    here is picked up by the training loop and the web UI without touching
    either.

    `name` must be SCREAMING_SNAKE_CASE (it becomes a skill name),
    `patterns` a non-empty list of (label, regex) pairs with unique
    labels, `description` one line for `python3 -m minagi.skills scope`.
    Raises ScopeError on a bad or duplicate name, a duplicate label or an
    uncompilable regex - a battery that cannot be trusted to run is not
    added half-way.
    """
    if not isinstance(name, str) or not re.match(r"^[A-Z][A-Z0-9_]*$", name):
        raise ScopeError(f"battery name must be SCREAMING_SNAKE_CASE "
                         f"(got {name!r})")
    if name == "security":
        raise ScopeError("'security' is the reserved group name")
    if name.lower() in (n.lower() for n, _, _ in _SECURITY_BATTERY):
        raise ScopeError(f"battery {name!r} is already registered")
    if not isinstance(patterns, (list, tuple)) or not patterns:
        raise ScopeError("patterns must be a non-empty list of "
                         "(label, regex) pairs")
    seen, pats = set(), []
    for item in patterns:
        if not (isinstance(item, (tuple, list)) and len(item) == 2):
            raise ScopeError("each pattern is a (label, regex) pair")
        label, rx = item
        if not label or not isinstance(label, str):
            raise ScopeError("a pattern label must be a non-empty string")
        if label in seen:
            raise ScopeError(f"duplicate pattern label {label!r}")
        seen.add(label)
        try:
            pats.append((label, re.compile(rx)))
        except re.error as exc:
            raise ScopeError(f"bad regex for {label!r}: {exc}") from exc
    _SECURITY_BATTERY.append((name, pats, description or "runtime battery"))
    GROUPS["security"].append(name)


def unregister_battery(name):
    """Remove a RUNTIME-registered battery again.

    The shipped batteries are part of the contract - the reports, the
    tests and the gate all assume them - and refuse to leave. An unknown
    name raises ScopeError too: removing nothing silently would hide the
    bug that called for it.
    """
    for i, (n, _, _) in enumerate(_SECURITY_BATTERY):
        if n == name:
            if any(n == f[0] for f in _FACTORY_BATTERY):
                raise ScopeError(f"{name!r} is a shipped battery - it is "
                                 f"part of the contract and is never removed")
            del _SECURITY_BATTERY[i]
            GROUPS["security"].remove(name)
            return
    raise ScopeError(f"unknown battery {name!r} - registered: "
                     f"{[n for n, _, _ in _SECURITY_BATTERY]}")


def scope_from_config(cfg):
    """The `skills.scope` list from a loaded config.yaml, ready for scan().

    Each entry is one of
        NAME                                   a registered battery
        {"battery": NAME}                      the same, spelled out
        {"skill": NAME}                        the same, spelled as a skill
        {"label": L, "regex": R, "skill": S?}  one ad-hoc pattern
    (so a config scope can mix bare battery names and pattern entries,
    exactly what scan() takes). Unknown keys, unknown battery/skill names
    and uncompilable regexes raise ScopeError HERE - at startup, where the
    operator is looking - instead of quietly shrinking the scan mid-run.
    An absent or empty scope returns [], which scan() reads as "everything
    registered".
    """
    from minagi.config import get
    scope = get(cfg or {}, "skills.scope")
    if scope is None:
        return []
    if not isinstance(scope, list):
        raise ScopeError("skills.scope must be a list of scope entries")
    known = [n for n, _, _ in _SECURITY_BATTERY]
    out = []
    for entry in scope:
        if isinstance(entry, str):
            if entry not in known:
                raise ScopeError(f"skills.scope names unknown battery "
                                 f"{entry!r} - registered: {known}")
            out.append(entry)
            continue
        if not isinstance(entry, dict):
            raise ScopeError(f"scope entries must be battery names or "
                             f"mappings (got {type(entry).__name__})")
        if "battery" in entry and ("label" in entry or "regex" in entry
                                   or "pattern" in entry):
            raise ScopeError("a scope entry is a battery OR a pattern, "
                             "not both")
        bad = [k for k in entry
               if k not in ("battery", "label", "regex", "pattern", "skill")]
        if bad:
            raise ScopeError(f"unknown scope key(s) {bad} - expected "
                             f"battery/skill/label/regex/pattern")
        if "battery" in entry or ("skill" in entry
                                  and "label" not in entry
                                  and "regex" not in entry
                                  and "pattern" not in entry):
            name = entry.get("battery") or entry.get("skill")
            if name not in known:
                raise ScopeError(f"skills.scope names unknown battery "
                                 f"{name!r} - registered: {known}")
            out.append({"battery": name})
            continue
        label = entry.get("label")
        regex = entry.get("regex", entry.get("pattern"))
        if not label or not regex:
            raise ScopeError("a pattern scope entry needs 'label' and "
                             "'regex' (or name a battery)")
        try:
            re.compile(regex)
        except re.error as exc:
            raise ScopeError(f"skills.scope pattern {label!r}: {exc}") from exc
        out.append({"label": label, "regex": regex,
                    "skill": entry.get("skill", "CUSTOM")})
    return out


def scan_scope(text, scope=None):
    """scan() under the config.yaml scope - the entry point serve.py and
    train.py call instead of raw scan(), so the configured scope is read
    at RUNTIME on every reply and every sample, not baked in at import.
    scope=None means "the configured scope, or everything registered when
    none is set"; a list replaces it wholesale."""
    from minagi.config import load
    if scope is None:
        scope = scope_from_config(load()) or None
    return scan(text, batteries=scope)


def scan(text, batteries=None):
    """Run the security battery over a sample, under a dynamic scope.

    The scope (the second argument - the knob that used to be baked in):

      * batteries=None            every REGISTERED battery runs - the eight
                                  shipped ones plus anything added at
                                  runtime with register_battery().
      * batteries=[entries...]    exactly that scope: battery names (or the
                                  equivalent {"battery": NAME}), and/or
                                  ad-hoc pattern instructions {"label",
                                  "regex", "skill"?}. An explicit EMPTY
                                  list is an empty scope - nothing runs and
                                  the sample passes, on purpose; pass None
                                  when you mean "the default".

    An unknown battery name or a pattern that does not compile raises
    ScopeError, so a typo can never quietly shrink the scan.

    Returns {"pass": bool, "findings": [...], "n": int}. A finding is a
    nomination for a human, not a verdict - `guarded` marks matches that sit
    in an obviously reflective/benign sentence. pass is False when there is
    at least one unguarded finding.
    """
    if batteries is None:
        batteries = [name for name, _, _ in _SECURITY_BATTERY]
    if not isinstance(batteries, (list, tuple)):
        raise ScopeError("batteries must be a list of battery names and/or "
                         f"pattern instructions (got "
                         f"{type(batteries).__name__})")
    registry_pats = {name: pats for name, pats, _ in _SECURITY_BATTERY}
    wanted = []                       # [(skill_name, [(label, rx), ...])]
    for item in batteries:
        if isinstance(item, str):
            if item not in registry_pats:
                raise ScopeError(f"unknown battery {item!r} - registered: "
                                 f"{list(registry_pats)}")
            wanted.append((item, registry_pats[item]))
        elif isinstance(item, dict):
            if "battery" in item:
                name = item["battery"]
                if name not in registry_pats:
                    raise ScopeError(f"unknown battery {name!r} - "
                                     f"registered: {list(registry_pats)}")
                wanted.append((name, registry_pats[name]))
                continue
            label = item.get("label")
            regex = item.get("regex", item.get("pattern"))
            if not label or not regex:
                raise ScopeError("a pattern scope entry needs 'label' and "
                                 "'regex' (or pass a battery name)")
            try:
                rx = re.compile(regex)
            except re.error as exc:
                raise ScopeError(f"bad pattern {label!r}: {exc}") from exc
            wanted.append((str(item.get("skill") or "CUSTOM"),
                           [(str(label), rx)]))
        else:
            raise ScopeError("a scope entry must be a battery name or a "
                             "{'label', 'regex'} instruction")
    findings = []
    for skill, pats in wanted:
        for hit in _battery(text, pats):
            hit["skill"] = skill
            findings.append(hit)
    unguarded = [f for f in findings if not f["guarded"]]
    return {"pass": not unguarded, "findings": findings, "n": len(findings),
            "unguarded": len(unguarded)}


# ---------------------------------------------------------------------------
# registry + reporting
# ---------------------------------------------------------------------------

GROUPS = {
    "text": ["CONTAINS", "CONTAINS_ALL", "CONTAINS_ANY", "CONTAINS_NONE",
             "EQUALS", "STARTS_WITH", "ENDS_WITH", "REGEX", "ONE_LINE",
             "LENGTH_LESS_THAN", "LENGTH_GREATER_THAN", "LENGTH_BETWEEN"],
    "wellformed": ["IS_JSON", "IS_EMAIL", "CONTAINS_VALID_LINK",
                   "NO_INVALID_LINKS"],
    "ir": ["BLEU_SCORE", "ROUGE_SCORE", "RECALL_SCORE", "PRECISION_AT_K",
           "RECALL_AT_K", "HIT_RATE", "MRR"],
    "similarity": ["LEVENSHTEIN_SIMILARITY", "NUMERIC_SIMILARITY"],
    "security": [name for name, _, _ in _SECURITY_BATTERY],
}


def registry():
    """name -> callable. Security skills expose run(text, **_) -> verdict,
    built over the batteries so the CLI and callers need no special case."""
    out = {n: globals()[n] for names in GROUPS.values() for n in names
           if n in globals()}

    def make(battery):
        def run(text, **_):
            r = scan(text, batteries=[battery])
            return _verdict(r["pass"], f"{r['n']} finding(s)") if r["n"] \
                else _ok("clean")
        run.__name__ = battery
        run.__doc__ = f"security battery {battery} over model output"
        return run

    for name in GROUPS["security"]:
        out[name] = make(name)
    return out


def run_skill(name, text=None, **params):
    """Uniform entry point. Text-first skills (CONTAINS, IS_JSON, ...) get
    the sample positionally or as text=; FA-signature skills (BLEU_SCORE
    takes reference=/hypothesis=) get everything through params, as FA
    spells it."""
    if text is None:
        text = params.pop("text", "")
    fn = registry().get(name)
    if fn is None:
        return _fail(f"unknown skill {name}")
    try:
        import inspect
        first = next(iter(inspect.signature(fn).parameters), "text")
    except (ValueError, TypeError):
        first = "text"
    try:
        if first in ("text", "output") and first not in params:
            return fn(text, **params)
        return fn(**params)
    except Exception as exc:          # fail closed, never crash the loop
        return _fail(f"error: {exc}")


def format_report(results, text="", batteries=None):
    """Human-readable block, the shape appended under training samples.
    `batteries` scopes the security section the way scan() takes it."""
    lines = ["<skills>"]
    if text:
        r = scan(text, batteries=batteries)
        if r["n"] == 0:
            lines.append("security: clean")
        else:
            head = "SECURITY REVIEW" if not r["pass"] else "security"
            lines.append(f"{head}: {r['n']} finding(s) "
                         f"({r['unguarded']} unguarded)")
            for f in r["findings"][:6]:
                flag = "" if f["guarded"] else " *"
                lines.append(f"  [{f['skill']}] {f['pattern']}: "
                             f"{f['snippet']!r}{flag}")
    for name, v in results:
        mark = "pass" if v["result"] is True else \
            (f"{v['result']:.3f}" if isinstance(v["result"], float) else "FAIL")
        lines.append(f"{name}: {mark}  {v['reason']}")
    lines.append("</skills>")
    return "\n".join(lines)


def format_scans(scans, limit=6):
    """Block for the training log: one scan per sample lane.
    `scans` is [(lane_name, scan_dict)]."""
    lines = ["<skills>"]
    total = sum(r["n"] for _, r in scans)
    if total == 0:
        lines.append("security: clean across "
                     f"{len(scans)} lane(s)")
    for name, r in scans:
        if r["n"] == 0:
            continue
        head = "!" if not r["pass"] else " "
        lines.append(f"{head} {name}: {r['n']} finding(s) "
                     f"({r['unguarded']} unguarded)")
        for f in r["findings"][:limit]:
            flag = "" if f["guarded"] else " *"
            lines.append(f"    [{f['skill']}] {f['pattern']}: "
                         f"{f['snippet']!r}{flag}")
    lines.append("</skills>")
    return "\n".join(lines)


def _parse_patterns(specs):
    """"LABEL=REGEX" flags -> {'label', 'regex'} scope instructions."""
    out = []
    for spec in specs:
        label, sep, regex = spec.partition("=")
        if not sep or not label or not regex:
            raise ScopeError(f"pattern must be LABEL=REGEX (got {spec!r})")
        out.append({"label": label, "regex": regex})
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main():
    import argparse
    ap = argparse.ArgumentParser(
        prog="python3 -m minagi.skills",
        description="skill evals over model output (Future AGI taxonomy, "
                    "native implementation)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list every skill by group")
    p_run = sub.add_parser("run", help="run one skill on a text")
    p_run.add_argument("skill")
    p_run.add_argument("--text", default=None)
    p_run.add_argument("--input", default=None, help="file to read")
    p_run.add_argument("--params", default="{}", help="JSON kwargs")
    p_scan = sub.add_parser("scan", help="run the security battery")
    p_scan.add_argument("--text", default=None)
    p_scan.add_argument("--input", default=None)
    p_scan.add_argument("--battery", action="append", metavar="NAME",
                        help="limit the scan to this battery (repeatable)")
    p_scan.add_argument("--pattern", action="append", metavar="LABEL=REGEX",
                        help="add one ad-hoc pattern to this scan "
                             "(repeatable)")
    p_scan.add_argument("--add-battery", metavar="NAME",
                        help="register this run's --pattern flags as a "
                             "battery named NAME instead of ad-hoc CUSTOM")
    sub.add_parser("scope", help="show the current scan scope (registered "
                                 "batteries + skills.scope from config.yaml)")
    args = ap.parse_args()

    if args.cmd == "list":
        for group, names in GROUPS.items():
            print(f"{group}:")
            for n in names:
                print(f"  {n}")
        return
    text = getattr(args, "text", None)
    if text is None and getattr(args, "input", None):
        with open(args.input, "r", errors="replace") as fh:
            text = fh.read()
    if args.cmd == "run":
        params = json.loads(args.params)
        v = run_skill(args.skill, text or "", **params)
        print(format_report([(args.skill, v)]))
        return
    if args.cmd == "scope":
        from minagi.config import load as _cfg_load
        print("registered batteries:")
        for n, _, d in _SECURITY_BATTERY:
            print(f"  {n:<26} {d}")
        try:
            cfg_scope = scope_from_config(_cfg_load())
        except ScopeError as exc:
            print(f"[scope] config.yaml: {exc}", file=sys.stderr)
            return 2
        if cfg_scope:
            print("skills.scope (config.yaml) replaces the default for "
                  "serve/train:")
            for e in cfg_scope:
                print(f"  {e}")
        else:
            print("skills.scope: not set - every registered battery runs")
        return 0

    if args.cmd == "scan":
        from minagi.config import load as _cfg_load
        try:
            pats = _parse_patterns(args.pattern or [])
            if args.add_battery:
                if not pats:
                    print("--add-battery needs at least one --pattern",
                          file=sys.stderr)
                    return 2
                register_battery(args.add_battery, pats)
                args.battery = (args.battery or []) + [args.add_battery]
                pats = []
            if args.battery or pats:
                scope = list(args.battery or []) + pats
            else:
                scope = scope_from_config(_cfg_load()) or None
            scan(text or "", batteries=scope)
            print(format_report([], text=text or "", batteries=scope))
        except ScopeError as exc:
            print(f"[scope] {exc}", file=sys.stderr)
            return 2
        return 0


if __name__ == "__main__":
    sys.exit(_main())
