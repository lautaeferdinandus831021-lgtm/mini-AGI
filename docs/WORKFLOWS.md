# WhiteHat_mini-AGI — App Workflows (detailed)

Every workflow the app runs, documented end to end: trigger, step-by-step
flow, the files involved, failure modes, and the command that drives it.
Companion to the architecture overview in `README.md`; the security decisions
and CWE mappings referenced here are indexed in
[`artifacts/FINDINGS_INDEX.md`](../artifacts/FINDINGS_INDEX.md) and stored as
queryable records under `knowledge/` (Workflow 7, `python3 -m minagi.knowledge`).

---

## Workflow 1 — Serve & chat (`serve.py`, the interactive path)

**Trigger:** `python3 serve.py --port 8080` (or `--no-learn` for read-only).

```
startup
  ├─ identity.banner() printed                minagi/identity.py
  ├─ weights/ loaded from manifest.json       minagi/store.py, recur.load_any
  │    (atomic .npz writes; the dir IS the model)
  ├─ LiveLearner constructed (learn mode)     minagi/live.py
  │    trunk at reduced LR, one optimiser per stream
  └─ Flask app on 0.0.0.0:PORT                serve.py

POST /api/chat  {messages:[...], max_new:N}
  ├─ build_prompt() packs the conversation + prime corpus slice
  │    into the last 90% of the context window
  ├─ LOCK acquired (one generation at a time — the model is shared)
  ├─ SSE stream, one event per character:
  │    stream(): KV cache primed on the prompt (pos_offset=0)
  │    per step: pick_next() greedy + adaptation trace
  │      (adapt_strength/decay from config; determinism kept:
  │       no RNG anywhere in decode.py)
  │    every reselect chars: choose_for(out) re-scores the working
  │      set; swaps only past pool.margin (hysteresis — most rechecks
  │      change nothing and emit no swap event)
  │    stop: </bot> marker or context ceiling
  ├─ done event:
  │    {done, n, cps, learn, pool, skills: scan(reply[:4000])}
  │      skills = the outbound security battery over what the model
  │      just wrote (minagi/skills.py — same evals as training)
  └─ remember(user, reply): the finished exchange is marked up
       (<user>/<bot>) and fed to LiveLearner.feed() → one optimiser
       step per `chunk` chars; step records stream back as "learned"

GET /api/state   → resident experts, learn counters (the page polls this)
GET /api/prime   → what the prompt is primed with
GET /api/skills  → {groups} listing; ?name=X&text=Y runs one skill
POST /api/skills {text} → full security battery over arbitrary text
GET /            → the page (title/brand from identity.APP_NAME)
```

**Failure modes (documented in-code):**
- `torch.cuda.OutOfMemoryError` → cache emptied, SSE error event ("something
  else is using the card"), socket stays up — dying here would close the tab.
- No reply text → no skills scan (nothing to judge), done event still sent.
- `remember()` reports `pending`/`chunk` even when no step was taken, so
  silence is never mistaken for broken learning.

**Files:** `serve.py`, `minagi/live.py`, `minagi/stream.py`, `minagi/decode.py`,
`minagi/skills.py`.

---

## Workflow 2 — Training / reading (`train.py read`, the batch path)

**Trigger:** `python3 train.py read <files-or-corpus> [--save] [--skills] ...`

```
ingest.py      walk dirs → byte-level chunk stream (no tokenizer to fit;
               binaries skipped by sampling, files read start-to-end)
   ▼
cmd_read() loop, one chunk per step:
   ├─ stream.py Reader: chunk → KV cache → forward → gradient step
   │    (graph bounded by chunk; cache bounded by context)
   ├─ paged.py  before each chunk: demand() scores what the text wants
   │    on hidden states the last chunk routed on → working-set swaps;
   │    Adam moments travel with the expert; identity-matched slots
   ├─ pool.py   growth brakes (room/used/earning/fits/honest) may add
   │    recombined experts; the pruner removes unaddressed ones
   ├─ plasticity.py  LR moves both ways on held-out evidence; trunk at
   │    0.1× expert LR is the anti-forgetting mechanism
   └─ every --sample-every minutes:
        sample_now() → 9 SAMPLE_PROMPTS lanes, raw + adapted variants
        write_samples() → runs/samples.txt:
           header (losses, context, grad norm, plasticity evidence)
           per-lane text + repeat_rate + chess_legality (checkable lane)
           [if --skills] raw lane → skills.scan() → <skills> block
             (deterministic → the log stays diffable)
   ├─ checkpoint every few minutes → weights/ (atomic tmp+rename),
   │    keeping the BEST state, not the newest
   └─ divergence repair: held-out > best × --revert-factor → reload
        weights/, halve LR, shrink context; stops after --max-reverts
```

**Failure modes:**
- A diverging run repairs itself rather than thrashing (revert factor).
- Sampling router is non-deterministic on CUDA (±0.014 between identical
  runs — documented; treat 0.03 as a real difference).
- Interrupted saves cannot corrupt `weights/` (write-then-rename).

**Files:** `train.py`, `minagi/{stream,paged,pool,plasticity,ingest,skills,store}.py`.

---

## Workflow 3 — Live learning inside chat

Not a separate mechanism — the same training path reached from serving:

```
chat exchange finished
   ▼
live.exchange_text() → "<user>\n…\n</user>\n<bot>\n…\n</bot>\n"
   ▼
LiveLearner.feed()  (LOCK held)
   buf.extend(ids) → every `chunk` chars: trim window → _step()
   _step(): forward on the last `context` chars, backward, clip, step
   steps counter + log record {step, chars, loss, grad_norm, note}
   ▼
every save_every steps → store.save() → weights/ updated under LOCK
```

The stream only advances (no re-reading), which keeps chat a lighter diet
than the dense regime `live.py` documents — and warns is still UNMEASURED.
Honest cost statement, not a hidden one.

**Files:** `minagi/live.py`, `serve.py` (`remember()`, `learn_state()`).

---

## Workflow 4 — Skill supply chain (inbound security)

**Trigger:** any agent-skill installation into this repo. Policy: **scan
first, install second; the scan runs before `npx skills add`, never after.**

```
bash scripts/skills_gate.sh <target> [targets...]
   ├─ [1] preflight: skillspector on PATH?  NO → exit 2 (fail closed:
   │        an unscannable skill is an uninstallable skill)
   ├─ [2] per target: skillspector scan --recursive --no-llm
   │        → JSON report in .skillspector/<slug>-<ts>.json
   │        (exit code discarded on purpose: non-zero means findings OR
   │         crash — the report file tells them apart)
   ├─ [3] report missing/empty  → BLOCKED (scanner error, no report) rc=1
   ├─ [4] classify from report: max_issue_severity
   │        HIGH/CRITICAL → BLOCK; MEDIUM/LOW → hardening notes, pass
   │        (NVIDIA's own catalog ships MEDIUMs — recorded, human decides)
   ├─ [5] report unparseable   → BLOCKED (unparseable report) rc=1
   └─ [6] summary + exit rc; SCAN_ONLY=1 downgrades everything to
            report-only and says so explicitly

then, only if the gate passed:
npx skills add <owner>/<repo> -s <skill> -y
   → .agents/skills/<skill>/ + agent symlinks + skills-lock.json
```

**Evidence from the trial run (2026-09-28):** of 12 scanned NVIDIA skills,
2 passed and were installed (`nemo-automodel-distributed-training` risk 0,
`nemo-automodel-recipe-development` risk 10); 10 blocked, including
`aiq-research` (100/CRITICAL, env-credential → network exfiltration) and
`warp-eval` (65/HIGH). Full table, CWE mapping and verbatim findings:
`artifacts/FINDINGS_INDEX.md`.

**Files:** `scripts/skills_gate.sh`, `.skillspector/` (gitignored reports),
`.agents/skills/`, `skills-lock.json`.

---

## Workflow 5 — Model-output scanning (outbound security)

The same `minagi/skills.py` engine serves three callers — one implementation,
three enforcement points, so the verdicts are always consistent:

| Caller | What is scanned | Where the verdict lands |
|---|---|---|
| `train.py write_samples(--skills)` | the **raw** variant of each sample lane (unguarded output — the adapted variant is steered by the decode rule, not the model; truncated to 4000 chars) | `<skills>` block in `runs/samples.txt` |
| `serve.py /api/chat` done event | the just-generated reply | `skills` field of the SSE done event (UI-usable) |
| `serve.py /api/skills`, `python3 -m minagi.skills` | arbitrary text | JSON / `<skills>` block |

Battery: 8 groups — PII, secrets, prompt-injection, unsafe-code, SQLi, XSS,
path-traversal, phishing — all deterministic regex batteries (no RNG, no LLM),
so identical input ⇒ identical verdict. A `guarded` flag marks matches inside
obviously reflective sentences ("never share your api key") as nominations,
not verdicts. All skills are fail-closed: an eval that throws returns
`{"result": false, "reason": "error: …"}`.

**The scope is dynamic, not a constant.** `scan()` reads its battery list
per call: `register_battery()` / `unregister_battery()` change what every
caller runs at runtime (shipped batteries can never be removed), and
`scope_from_config()` turns the `skills.scope` list in `config.yaml` into
the scope `scan_scope()` - the entry point both serve.py and train.py call -
resolves at RUNTIME on every reply and every sample log. An absent scope
means "everything registered"; a typo in the config raises `ScopeError` at
startup instead of quietly scanning less.

**Files:** `minagi/skills.py`, `train.py`, `serve.py`.

---

## Workflow 6 — Test & verification (quality gate)

**Trigger:** `bash scripts/test_sandbox.sh` (default), `KEEP=1` to inspect.

```
mktemp -d /tmp/miniagi-test-XXXX
   ├─ git archive HEAD → byte-identical checkout (misbehaving tests
   │    cannot touch the working tree)
   ├─ snapshot: git status count + git diff fingerprint
   ├─ [1] py_compile every repo .py            (in the checkout)
   ├─ [2] minagi.skills regression: 33-skill registry, contract tests,
   │      security battery (secret→block, benign→clean, reflective→guarded),
   │      CLI list/run
   ├─ [3] skills_gate.sh × 5 exit paths against a stub scanner +
   │      synthetic skill built INSIDE the sandbox (stub PATH wins over
   │      any real scanner): clean→0, HIGH→1, SCAN_ONLY→0,
   │      no-scanner→2, corrupt-report→1
   ├─ [4] minagi.store surface (auto-SKIPs without torch)
   ├─ [5] hygiene: status count + diff fingerprint unchanged →
   │      the working tree comes out exactly as it went in
   └─ rm -rf sandbox (KEEP=1 keeps it), exit 0 iff all passed
```

**Why it exists:** several earlier defects (scanner mislabelled findings as
errors, an unparseable report that could pass, a stale incremental build
that made a UAF PoC look fixed) were all caught by exactly this shape of
discipline. The suite encodes them so they cannot come back quietly.

**Files:** `scripts/test_sandbox.sh`.

---

## Workflow 7 — Report knowledge management (recall, not just records)

**Trigger:** after any bounty/assessment report is produced, and whenever a
question about past work needs an answer.

```
a report lands (submission, verification, negative result, gate trial)
   ▼
minagi/knowledge.py save()  →  knowledge/<id>.json
   ├─ validate() rejects anything a query would trip over: required fields,
   │    status/report_type enums, YYYY-MM-DD dates, slug ids, timeline and
   │    evidence shapes - the enum a filter runs on cannot silently drift
   └─ atomic write (tmp + rename, the store.py discipline); no silent
        overwrite - replace on purpose with overwrite=True

recall, when it is needed:
   ├─ python3 -m minagi.knowledge list [--status S] [--target T] [PATTERN]
   ├─ python3 -m minagi.knowledge search WORD... [--status S]   (AND, full text)
   ├─ python3 -m minagi.knowledge show ID [--markdown]  (triager-readable)
   ├─ python3 -m minagi.knowledge timeline [--status S] (merged, newest first)
   ├─ python3 -m minagi.knowledge stats                 (where do we stand)
   └─ python3 -m minagi.knowledge add FILE.json [--overwrite]

the record is the unit of knowledge: title/program/target/status/CWE/dates,
a timeline of dated facts, key_facts that carry the conclusions, evidence
pointers (gitignored raw proof stays where it is), regeneration commands,
and lessons - the part worth keeping forever.

**The testing scope is dynamic too.** Which targets/programs the workspace
is watching lives in `knowledge/scope.json` (entries of {target, program,
added, status, note}), not in any hardcoded list: `scope_targets()` answers
"what are we watching", `save()` grows the scope automatically the first
time a record names a new target, and `scope-add` / `scope-status` /
`scope-remove` edit it on purpose. `python3 -m minagi.knowledge stats`
reports it next to the record counts.

```bash
python3 -m minagi.knowledge scope
python3 -m minagi.knowledge scope-add TARGET [--program P] [--note N]
python3 -m minagi.knowledge scope-status TARGET STATUS
python3 -m minagi.knowledge scope-remove TARGET
```

**The testing scope is dynamic too.** Which targets/programs the workspace
is watching lives in `knowledge/scope.json` (entries of {target, program,
added, status, note}), not in any hardcoded list: `scope_targets()` answers
"what are we watching", `save()` grows the scope automatically the first
time a record names a new target, and `scope-add` / `scope-status` /
`scope-remove` edit it on purpose. `python3 -m minagi.knowledge stats`
reports it next to the record counts.

```bash
python3 -m minagi.knowledge scope
python3 -m minagi.knowledge scope-add TARGET [--program P] [--note N]
python3 -m minagi.knowledge scope-status TARGET STATUS
python3 -m minagi.knowledge scope-remove TARGET
```
```

Seeded from the real tracks: `curl-referer-uaf` (H1 #3971462,
n/a-informational), `crypto-graphql-negative` (resolved, nothing to report),
`nvidia-skills-gate-trial` (resolved, 2 installed / 10 blocked).

**Failure modes (documented in-code):**
- A record that would sort wrongly or render half a report is worse than one
  that refuses to be saved - validation is at write time, not read time.
- A broken record on disk is skipped by reads, never fatal to the store.

**Files:** `minagi/knowledge.py`, `knowledge/*.json`.

---

## Workflow map (who calls whom)

```
                    scripts/skills_gate.sh          scripts/test_sandbox.sh
                           │ (blocks installs)              │ (verifies)
                           ▼                                ▼
   .agents/skills/ ──► coding agents read SKILL.md ──► code enters repo
                                                            │
              ┌─────────────────────────────────────────────┘
              ▼
        train.py read ──► minagi/stream+paged+pool+plasticity ──► weights/
              │                                                    │
              ▼ (sample log + skills scan)                         ▼
        runs/samples.txt                                      serve.py loads
                                                                    │
   user ◄── SSE chat ◄── serve.py ──► LiveLearner.feed() ───────────┘
                │                        (same stream path, learns live)
                └─ reply scanned ──► minagi/skills.py (outbound battery)
```

---

## Quick reference

| Goal | Command |
|---|---|
| Serve & chat | `python3 serve.py --port 8080` |
| Train/read files | `python3 train.py read <dir> --save --skills` |
| Scan a skill before installing | `bash scripts/skills_gate.sh <target>` |
| Recall a past report / its timeline | `python3 -m minagi.knowledge search|show|timeline …` |
| Install a gated skill | `npx skills add NVIDIA/skills -s <skill> -y` |
| Scan model output ad hoc | `python3 -m minagi.skills scan --input f.txt` |
| List every eval | `python3 -m minagi.skills list` |
| Run the whole test suite | `bash scripts/test_sandbox.sh` |
| App identity / banner | `python3 -m minagi.identity` |
