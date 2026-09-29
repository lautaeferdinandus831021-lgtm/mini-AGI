# Testing WhiteHat_mini-AGI in Google Cloud Shell

WhiteHat_mini-AGI is hardened end to end: skills gated on the way in, output
scanned on the way out. This guide runs the whole app — its test gate, a
real training read, and the chat UI — on a machine that has what this repo's
runtime wants: full Linux tooling, pip, and an ephemeral VM you can point at
a GPU when you have one.

[Google Cloud Shell](https://shell.cloud.google.com/?pli=1&show=ide%2Cterminal)
gives you a free ephemeral VM (Debian, ~5–6 GB RAM, and — important for this
repo — an **ephemeral disk that resets when the session ends**). Cloud Shell
also bundles the `gcloud` CLI, so everything here works in either the
Terminal tab or the Editor tab.

What works out of the box on that VM, and what needs more:

| What | On Cloud Shell |
|---|---|
| `scripts/test_sandbox.sh` (the full test gate) | ✅ runs as-is |
| `python3 -m minagi.skills` (33 evals + security battery) | ✅ runs as-is |
| `train.py read` / `serve.py` (torch runtime) | ✅ after Step 2 (small VM: low-memory profile of Step 5) |
| Real GPU training | ❌ not on the default VM — see "GPU" below |

---

## Step 0 — Open the shell

Open
[shell.cloud.google.com](https://shell.cloud.google.com/?pli=1&show=ide%2Cterminal)
and sign in with any Google account (a billing account is **not** required).
Wait for the terminal prompt.

> The `$HOME` disk (5 GB, persisted) survives between sessions; the rest of
> the VM's disk does not. Everything below installs into `$HOME` or a
> scratch dir, so a fresh session only needs Step 1–2 again.

## Step 1 — Clone the repository

```bash
git clone https://github.com/lautaeferdinandus831021-lgtm/mini-AGI.git
cd mini-AGI
```

## Step 2 — Install the runtime dependencies

Cloud Shell's Python 3 already includes pip. The app's runtime needs four
packages (plus `chess` only if you want the chess-legality metric in the
sample log):

```bash
pip install --user torch numpy pyyaml matplotlib flask chess \
    --index-url https://download.pytorch.org/whl/cpu \
    --extra-index-url https://pypi.org/simple
```

**Use the CPU index.** Plain `pip install torch` pulls the CUDA build: the
torch wheel alone drags in every `nvidia-*-cu13` library, which measured at
~5.8 GB in `~/.local` (plus a ~3 GB pip cache) against the 5 GB persistent
`$HOME` Cloud Shell gives you - it does not fit. The CPU build is ~1 GB and
everything in this guide runs identically on it (verified: the full test
gate reports PASS=11 either way). Only the GPU section below wants the
CUDA build, and there it comes preinstalled with the Deep Learning VM
image.

Notes:

- `--user` installs into `$HOME/.local`, which **does** survive a session
  reset (part of the 5 GB persistent `$HOME`).
- Optional extras, only for building corpora: `pip install --user
  zstandard datasets scipy`.

Verify:

```bash
python3 -c "import torch, numpy, yaml, matplotlib, flask; print('runtime OK')"
```

## Step 3 — Run the full test gate (no GPU needed)

```bash
bash scripts/test_sandbox.sh
```

Expected tail of the output:

```
== 6. working tree untouched by the whole run ==
  PASS git status unchanged (0 untracked/marked entries before and after)
  PASS git diff fingerprint unchanged by the run
[result] PASS=12 FAIL=0
```

Twelve passes, zero failures, and the working tree byte-identical to `HEAD`
afterwards. (In an environment without torch or flask the targeted
serve-route checks and the store-surface check skip, and the count reads
PASS=10 FAIL=0.) `KEEP=1 bash scripts/test_sandbox.sh` keeps the throwaway
checkout under `/tmp` for inspection.

The gate has six sections: py_compile of the whole tree, the full
`minagi.skills` regression, all five exit paths of the `skills_gate.sh`
security gate, the targeted regression tests for the most recent fixes
(`tests/test_targeted.py` - serve.py identity and routes, whole-character
SSE decoding, the train.py growth-line print on CPU and CUDA, minagi/stream,
minagi/paged, minagi/live, minagi/plasticity and minagi/knowledge
invariants; sections that
need torch or flask skip cleanly without them), the `minagi.store` surface
(now **executed**, not skipped, because torch is present), and the tree
hygiene check.

## Step 4 — Skills CLI smoke test

```bash
python3 -m minagi.skills list
python3 -m minagi.skills scan --text 'the password: hunter22 is in the vault'
```

The scan must exit with a `!` finding (a real secret pattern). A benign
string must come back clean:

```bash
python3 -m minagi.skills scan --text 'a quiet day in the park with a ball'
```

## Step 5 — Train (CPU is fine for a smoke test)

Create the model directory (from `config.yaml`) and read something:

```bash
# held-out folder, so the run reports before/after and the learning-rate
# controller has something to steer by
mkdir -p data/val/general
printf 'Held-out text about routing, experts and continual reading.\n' \
    > data/val/general/val.txt

# low-memory profile for a small VM - see the note below
python3 -u train.py read data/train --passes 1 --sample-every 0.1 \
    --minutes 0.3 --save --skills \
    --resident 8 --ram-capacity 8 --chunk 128 \
    --context-start 512 --context-end 512 \
    --sample-chars 8 --eval-chars 2048 --sample-eval-chars 1024 --no-plots
```

> **Why these flags.** The default profile (32 resident experts, a 2,048
> window, depth sampled around 14 of 24 rows) needs several GB of RAM: on a
> ~2 GB VM the first gradient step is OOM-killed by the kernel before any
> output appears (measured at ~1.8 GB RSS, silent death). `--resident 8`
> shrinks the working set, `--chunk 128 --context-* 512` shrink the
> autograd graph, and the `--sample-*/--eval-*` knobs keep the CPU-bound
> sampling and evaluation rounds short - on one CPU core each sampling
> round (10 prompt lanes, depth-24 forwards) and the held-out evaluation
> take minutes; `--minutes 0.3` keeps the step loop short so one sampling
> round happens at the end and the whole run finishes in roughly ten
> minutes. `-u` prints progress as it happens instead of buffering it
> (unbuffered matters whenever output goes to a file or pipe). All of
> these are ordinary `train.py read` knobs; on the GPU VM in the section
> below, the defaults are fine and you can drop the micro-knobs.

What to watch for in the output:

- `params ... | 64 experts | block-applications ...` — the pool is live.
- `before:` / `after:` held-out lines — the cost of reading is measured,
  not assumed.
- `sample log` entries in `runs/samples.txt` (raw and adapted readings per
  prompt lane, plus an `<skills>` block from `--skills` when any finding
  fires).
- `weights/ updated` at the end — the checkpoint (with Adam moments in
  `optim.npz`) is on disk.
- With `--save`, growth may fire: the pool can end the run with more
  experts than it started with (`pool N experts (+1)` in the log).

Measured while executing this guide end to end on a 1-core, 2 GB VM:
`before: 5.6400 +/-0.0923` → `after: 5.6324 +/-0.0880`, pool grew 64→65
experts, `weights/` written as 65 expert files + 3 bundles (~1.6 GB paged
layout on disk). Loss numbers are poor at this scale — the point is that
the whole read path executes.

## Step 6 — Serve and chat

```bash
python3 serve.py --port 8080
```

Open the Web Preview (Cloud Shell Editor → Web Preview → *Preview on port
8080*) or the URL it prints. In the UI:

- Type a message — characters stream in one by one (SSE), the two
  mechanism meters move (long-term memory / working set), and expert chips
  appear as the working set changes.
- Open `http://127.0.0.1:8080/api/skills` for the skill registry, and
  `/api/state` for live counters.
- `Ctrl-C` stops the server. `--no-learn` serves read-only (no weight
  updates, no writes to `weights/`).

On a small VM, learning while serving doubles the memory footprint; serve
the checkpoint without it, or with a smaller live-learning chunk:

```bash
python3 serve.py --port 8080 --no-learn          # read-only
python3 serve.py --port 8080 --learn-chunk 128   # or lighter learning
```

No browser handy? The same conversation is a one-line POST (small
`max_new` keeps the CPU-bound generation short):

```bash
curl -sN -X POST http://127.0.0.1:8080/api/chat \
    -H 'Content-Type: application/json' \
    -d '{"messages":[{"role":"user","content":"hello"}],"max_new":8}'
```

Expect a `swap` event (the working set the prompt chose), `t` events for
the streamed characters, and a `done` event carrying the learning counter
and the security scan of the reply. Fewer `t` events than `max_new` is
correct, not truncation: generation emits whole UTF-8 characters, so
multi-byte tokens are held back until complete.

## GPU (optional)

The default Cloud Shell VM has **no GPU**. To actually train on one:

1. Open Cloud Shell, then run `gcloud config set project YOUR_PROJECT_ID`
   (a project with billing is required for GPUs).
2. Request a quota increase for one of the GPU types in your region, or use
   a region where you already have quota (`gcloud compute regions list`).
3. Launch a VM, SSH in from Cloud Shell, and run Steps 1–2 and 5–6 there:

   ```bash
   gcloud compute instances create whitehat-miniagi \
     --zone=us-central1-a --machine-type=n1-standard-8 \
     --accelerator=type=nvidia-tesla-t4,count=1 \
     --image-family=pytorch-latest-gpu --image-project=deeplearning-platform-images \
     --maintenance-policy=TERMINATE
   gcloud compute ssh whitehat-miniagi --zone=us-central1-a
   ```

   Inside that VM:

   ```bash
   nvidia-smi          # confirm the card
   git clone https://github.com/lautaeferdinandus831021-lgtm/mini-AGI.git
   cd mini-AGI
   pip install numpy pyyaml matplotlib flask chess   # torch ships in the image
   python3 train.py read data/train --passes 1 --save --device cuda
   ```

The app auto-detects CUDA (`--device cuda` default when a card is present);
`--precision bf16` is the default and only meaningful on GPU.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `externally-managed-environment` from pip | Use `pip install --user ...` (or `pip install --break-system-packages ...`). |
| `ModuleNotFoundError: flask` | You skipped Step 2, or the session reset — rerun it. |
| `bash scripts/test_sandbox.sh` FAIL on git hygiene | You have uncommitted changes — `git stash` or commit them first; the hygiene check is working as intended. |
| Blank page on port 8080 | Web Preview proxies only `http://127.0.0.1:8080` — start serve.py without `--host 0.0.0.0`, or set `--host 127.0.0.1`. |
| Torch says CUDA unavailable | Default Cloud Shell VM has no GPU — see the GPU section. |
| `no model in weights/` | Run Step 5 first (it creates the model from `config.yaml`). |
| Training dies silently after the first forward (no traceback) | The kernel OOM-killed it - the default profile needs several GB of RAM. Use the low-memory flags of Step 5, or move to the GPU VM. |
| Output appears only when the run ends | stdout is block-buffered when redirected - run with `python3 -u` (Step 5 does) or leave it attached to the terminal. |
| Sampling / evaluation rounds crawl on CPU | They run depth-24 forwards per prompt lane. Trim `--sample-chars`, `--eval-chars` and `--sample-eval-chars` (see Step 5). |

## Related docs

- [`docs/WORKFLOWS.md`](WORKFLOWS.md) — every app workflow in detail
- `README.md` → "Running the tests (sandboxed)" — what the test gate covers
- `artifacts/FINDINGS_INDEX.md` — the skill-supply-chain decision table and
  evidence locations
