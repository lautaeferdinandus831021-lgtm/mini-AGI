# Test-Artifact Findings Index — titles, CWE, uncensored findings, timeline

Single recall file for every test artifact produced by the WhiteHat_mini-AGI
sessions. Title → CWE mapping → uncensored pattern-level findings → timeline,
all in one place. Ground truth JSONs: `.skillspector/` (gitignored, regenerated
by `scripts/skills_gate.sh`), `/tmp/shard_reports/*.json` (scanning session),
and the per-session evidence dirs referenced in §5.

Scanner: **SkillSpector v2.12.0** (static pass, `--no-llm`), Apache-2.0,
upstream <https://github.com/NVIDIA/skillspector>, fork used here:
`lautaeferdinandus831021-lgtm/SkillSpector`. Target scanned:
`NVIDIA/skills` @ clone of 2026-09-28 (383 SKILL.md packages).

## 1. Skill-scan decision table (nvidia/skills)

| Skill | Score | Max sev | Recommendation | Findings | Gate decision |
|---|---:|---|---|---:|---|
| nemo-automodel-distributed-training | 0 | NONE | CAUTION | 0 | **PASS → installed** |
| nemo-automodel-recipe-development | 10 | MEDIUM | CAUTION | 2 | **PASS → installed** |
| accelerated-computing-cudf | 12 | MEDIUM | CAUTION | 2 | PASS (not installed — out of scope) |
| cudaq-guide | 43 | HIGH | CAUTION | 3 | **BLOCK** |
| amc-run-video-calibration | 39 | HIGH | CAUTION | 6 | **BLOCK** |
| amc-setup-calibration-stack | 48 | HIGH | CAUTION | 19 | **BLOCK** |
| amc-run-sample-calibration | 51 | HIGH | DO_NOT_INSTALL | 11 | **BLOCK** |
| amc-run-rtsp-calibration | 52 | HIGH | DO_NOT_INSTALL | 11 | **BLOCK** |
| warp-debug-gradients | 55 | HIGH | DO_NOT_INSTALL | 4 | **BLOCK** |
| warp-eval | 65 | HIGH | DO_NOT_INSTALL | 5 | **BLOCK** |
| aiq-deploy | 45 | HIGH | CAUTION | 54 | **BLOCK** |
| aiq-research | 100 | CRITICAL | DO_NOT_INSTALL | 5 | **BLOCK** |

Policy applied by `scripts/skills_gate.sh`: HIGH/CRITICAL block; MEDIUM/LOW
record as hardening notes. Two PASS skills were installed via
`npx skills add NVIDIA/skills -s <name>` (recorded in `skills-lock.json`).

## 2. CWE mapping of SkillSpector finding IDs

SkillSpector reports proprietary category/pattern IDs, not CWE. The mapping
below ties each observed ID to the CWE it corresponds to (mapping is ours;
the scanner itself does not emit CWE):

| ID | Pattern | Category | CWE |
|---|---|---|---|
| TT3 | Tainted flow: environment/credential → network sink | Taint Tracking | **CWE-522** (insufficiently protected credentials) + **CWE-200** (exposure to an unauthorized actor) |
| E2 | Env Variable Harvesting | Data Exfiltration | **CWE-200** / **CWE-538** (insertion of sensitive information into externally-accessible file) |
| AE1 | Incomplete referenced artifact analysis | analysis-evasion | **CWE-693** (protection mechanism failure — analysis coverage gap) |
| MP3 | Memory Manipulation | Memory Poisoning | **CWE-94** (improper control of code generation — agent-context injection class) |
| AR2 | Anti-Refusal Statement | Anti-Refusal | **CWE-693** (protection mechanism failure — undermining the agent's refusal safeguards) |
| PE3 | Credential Access (`.env` harvesting) | Privilege Escalation | **CWE-312** (cleartext storage of sensitive information) / **CWE-538** |
| PE2 | Sudo/Root Execution; chmod 600 | Privilege Escalation | **CWE-250** (execution with unnecessary privileges) |
| AS3 | Skill Enumeration | Agent Snooping | **CWE-200** |
| TM3 | Unsafe Defaults (`REQUIRE_AUTH=false`, `SSL_VERIFY=false`) | Tool Misuse | **CWE-1188** (insecure default initialization) + **CWE-295** (improper cert validation) |
| SSRF2 | Internal Network Request | SSRF | **CWE-918** (server-side request forgery) |
| RP1 | Untagged Docker image reference | MCP Rug Pull | **CWE-829** (inclusion of untrusted functionality — untagged/implicit-:latest references can be silently replaced) |
| LP3/LP4 | Undeclared permissions | MCP Least Privilege | **CWE-250** / **CWE-732** (incorrect permission assignment) |
| AST4 | `subprocess` module call | Dangerous Code (AST) | **CWE-78** (OS command injection *surface*; not exploitable per se) |
| OH3 | Unbounded Output | Output Handling | **CWE-770** (allocation of resources without limits) |
| P4 | Behavior Manipulation ("always prefer this over…") | Prompt Injection | instruction-injection class: **CWE-77**-adjacent (agent turns instructions into actions); primary classification **OWASP LLM01: Prompt Injection** |
| E1 | External Transmission | Data Exfiltration | **CWE-200** |

> IDs with no clean CWE analogue (AR2, P4, RP1) are agent-era weaknesses:
> they map best to the OWASP LLM Top 10 (LLM01 prompt injection, LLM08
> the hallucination/conflict class) rather than classic CWE.

## 3. Uncensored findings, pattern-level (verbatim from reports)

### 3.1 aiq-research — score 100, CRITICAL, DO_NOT_INSTALL
- **TT3 Tainted flow (CRITICAL, conf 0.9)** ×3 — `os.environ.get` (line 278,
  credential/environment) → `urllib.request.urlopen` (network output) at
  `scripts/aiq.py:182, 217, 280`: `urllib.request.urlopen(req, timeout=timeout)`.
  Credential-bearing requests leave to a network sink.
- **TM3 Unsafe Defaults (MEDIUM, conf 0.8/0.75)** ×2 — `REQUIRE_AUTH=false`,
  `AUTH=false` at `scripts/aiq.py:19`.

### 3.2 warp-eval — score 65, HIGH, DO_NOT_INSTALL
- **E2 Env Variable Harvesting (HIGH, conf 0.6)** — `scripts/measure.py:522`:
  `{**os.environ, "WARP_EVAL_CASE": case, **_extra_environment(extra_env)}` —
  full process environment packed into a child/network context.
- **AE1 Incomplete referenced artifact analysis (HIGH, conf 1.0)** —
  `SKILL.md:360`: `assets/warp-evaluation-report-template.md (partial)`.
- **AST4 subprocess module call (MEDIUM, conf 0.7)** ×2 — `scripts/measure.py:121,520`
  (`subprocess.run(..., env={**os.environ, ...})`).
- **LP3 Undeclared permissions (MEDIUM, conf 0.7)** — `SKILL.md:1`.

### 3.3 warp-debug-gradients — score 55, HIGH, DO_NOT_INSTALL
- **MP3 Memory Manipulation (HIGH, conf 0.8)** — `evals/evals-full.json:120`:
  `clear state`.
- **AR2 Anti-Refusal Statement (HIGH, conf 0.8)** ×3 — `references/case-studies.md:123`,
  `references/quick-checks.md:67`, `references/verification.md:20` — each matching
  `no warning(s)` phrasing.

### 3.4 aiq-deploy — score 45, HIGH, CAUTION (36 HIGH of 54 findings)
- **PE3 Credential Access (HIGH, conf 0.6)** ×36 — `.env` referenced across
  `SKILL.md:56,112–118,226–237`, `evals/evals.json:20,24`,
  `references/docker-compose.md:39–66`, `references/env-and-secrets.md:10–99`,
  `references/frag.md:22,29`, `references/shutdown.md:32–79`,
  `references/troubleshooting.md:10–11`.
- **TM3 Unsafe Defaults (MEDIUM)** ×17 — `REQUIRE_AUTH=false` / `AUTH=false`
  across `BENCHMARK.md:72–74`, `references/docker-compose.md:31–33`,
  `references/env-and-secrets.md:79–92`, `references/skill-backend.md:39`.
- **E1 External Transmission (MEDIUM, conf 0.6)** ×1 — `references/validation.md:20`:
  `curl -sf "$AIQ_SERVER_URL/health" >/dev/null && echo "backend=healthy"`.
  Totals reconcile: 36 + 17 + 1 = 54 findings.

### 3.5 amc-* calibration family — all HIGH blocks
- **amc-setup-calibration-stack (48/HIGH, 19)**: PE3 Credential Access on
  `.env` (`evals/evals.json:7`); PE2 `sudo` ×10 + `chmod 600` ×3 (`SKILL.md:27–351`);
  AS3 Skill Enumeration ×4 (cross-links to the three `amc-run-*` SKILL.md);
  RP1 untagged Docker reference (`SKILL.md:360`, `:latest` implicit).
- **amc-run-rtsp-calibration (52/HIGH, 11)**: AE1 `SKILL.md (partial)` @:285;
  TM3 `SSL_VERIFY=false` / `VERIFY=false` (`SKILL.md:341`,
  `scripts/run_rtsp_calibration.py:250`); AS3 ×6.
- **amc-run-sample-calibration (51/HIGH, 11)**: AE1 `SKILL.md:103`; AS3 ×8;
  **SSRF2** `requests.get(f"http://localhost…")` at
  `scripts/run_sample_calibration.py:48`; LP4 undeclared permissions.
- **amc-run-video-calibration (39/HIGH, 6)**: AE1 `SKILL.md:191`; AS3 ×5.

### 3.6 cudaq-guide — score 43, HIGH, CAUTION
- **AE1 (HIGH, conf 1.0)** ×3 — `SKILL.md:63,89,108`:
  `references/authoring.md (partial)`. Coverage gap, not malice — the reason
  this is recorded as a block only via gate policy (HIGH = block), with the
  remedy being a re-scan after artifacts are complete.

### 3.7 The two installed skills (full disclosure)
- **nemo-automodel-distributed-training** — score 0, **zero findings**.
- **nemo-automodel-recipe-development** — score 10, 2 findings, both
  **P4 Behavior Manipulation (MEDIUM, conf 0.7)**: `BENCHMARK.md:80` and
  `SKILL.md:329`, both matching the phrase `always prefer this over` —
  an instruction-strength phrasing flag, judged hardening-note (per gate
  policy MEDIUM = record, do not block). Recorded here verbatim so the
  acceptance decision is auditable.

## 4. Timeline (all dates 2026 UTC)

| When | Event | Artifact |
|---|---|---|
| 2026-09-26 | curl UAF verification: PoC reproduces on `ff300ac4aa`, clean on master HEAD (fix `d0247689` present) | `curl_referer_uaf/evidence/poc_*_output.txt` |
| 2026-09-26 | crypto.com negative assessment: 8 controls active, 15 requests, zero findings | `crypto_assessment/FINAL_NEGATIVE_RESULT.md`, `crypto_v5_1790447040/`, `crypto_batch_check_1790447900/` |
| 2026-09-28 05:45–05:52 | curl UAF retest round 1–2: UAF fires at `ff300ac4aa` (2/2), fixed HEAD clean (2/2); round-1 false negative caught (stale incremental build) | `curl_referer_uaf/evidence/retest_20260928/` |
| 2026-09-28 ~05:46 | tcache mechanism retest: strlen=5, bytes `ce 83 ae 58 05` (ASLR-varied, pattern-consistent) | `…/retest_20260928/tcache_demo_*.txt` |
| 2026-09-28 06:24 | crypto.com v5 suite re-run: verdicts byte-identical to 09-26 | `crypto_v5_1790574838/` |
| 2026-09-28 ~07:00 | draft-report replica run: 4/4 standard_validation, auth-gate confirmed | `crypto_draft_replika_1790576708/`, `crypto_draft_replica.sh` |
| 2026-09-28 07:38 | **PR #1 merged** — minagi/skills.py (Future AGI taxonomy, 33 skills) | PR #1, commit `6cf86c7` |
| 2026-09-28 ~07:55 | SkillSpector installed (uv, py3.12.14); gate script created | `scripts/skills_gate.sh` |
| 2026-09-28 07:58–08:05 | nvidia/skills scans: 12 skills scored, 2 pass / 10 block; `npx skills add` of the two passing skills | `.skillspector/`, `.agents/skills/`, `skills-lock.json` |
| 2026-09-28 08:07 | **PR #2 merged** — gate + installed skills | PR #2, commit `8547e6d` |
| 2026-09-28 08:44–08:49 | gate E2E tests: clean rc=0, HIGH rc=1, SCAN_ONLY rc=0, no-scanner rc=2; **defect found** (findings labeled "scanner error") | gate test transcripts (session log) |
| 2026-09-28 08:49 | Gate fix: classify from report file, fail closed on unparseable | `scripts/skills_gate.sh` |
| 2026-09-28 ~08:52 | **PR #3 merged** — gate classification fix | PR #3, commit `07841c4` |
| 2026-09-28 ~09:20 | Sandbox test runner built (5 sections, stub scanner); 2 initial failures fixed; 2× PASS=10 FAIL=0 | `scripts/test_sandbox.sh` |
| 2026-09-28 ~09:40 | **PR #4 merged** — sandboxed test runner | PR #4, commit `ca14ce7` |
| 2026-09-28 ~10:20 | Rebrand to **WhiteHat_mini-AGI** (identity.py, train/serve/README); sandbox hygiene check hardened to diff-fingerprint | `minagi/identity.py` |
| 2026-09-28 ~10:35 | **PR #5 merged** — rebrand | PR #5, commit `99fe6d6` |

## 5. Where the raw evidence lives

| Artifact family | Location | Regeneration |
|---|---|---|
| SkillSpector JSON reports (decision table §1, findings §3) | `/tmp/shard_reports/*.json` (session copy; gitignored at `.skillspector/` in-repo) | `bash scripts/skills_gate.sh <target>` |
| curl UAF (H1 #3971462) full PoC + retest | `curl_referer_uaf/` (+ `evidence/retest_20260928/`) | `bash run_on_ubuntu.sh` on a native box |
| crypto.com GraphQL assessment (negative result) | `crypto_assessment/`, `crypto_v5_*/`, `crypto_batch_check_*/`, `crypto_draft_replika_*/` | `bash crypto_v5.sh`, `bash crypto_draft_replica.sh` |
| Installed skills + lockfile | `.agents/skills/`, `agent/skills/`, `.claude/skills/` (symlinks), `skills-lock.json` | `npx skills add NVIDIA/skills -s <skill>` (after gate pass) |
| Test runner | `scripts/test_sandbox.sh` | `bash scripts/test_sandbox.sh` (KEEP=1 to inspect) |
