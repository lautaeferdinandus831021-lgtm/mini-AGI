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
| `train.py read` / `serve.py` (torch runtime) | ✅ after Step 2 |
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
pip install --user torch numpy pyyaml matplotlib flask chess
```

Notes:

- `--user` installs into `$HOME/.local`, which **does** survive a session
  reset (part of the 5 GB persistent `$HOME`).
- Torch wheel is ~800 MB — the first install takes a few minutes.
- Optional extras, only for building corpora: `pip install --user zstandard
  datasets scipy`.

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
== 5. working tree untouched by the whole run ==
  PASS git status unchanged (0 untracked/marked entries before and after)
  PASS git diff fingerprint unchanged by the run
[result] PASS=11 FAIL=0
```

Eleven passes, zero failures, and the working tree byte-identical to `HEAD`
afterwards. (In an environment without torch the store-surface check skips
and the count reads PASS=10 FAIL=0.) `KEEP=1 bash scripts/test_sandbox.sh`
keeps the throwaway checkout under `/tmp` for inspection.

This is the same gate that runs in the project sandbox — five sections:
py_compile of the whole tree, the full `minagi.skills` regression, all five
exit paths of the `skills_gate.sh` security gate, the `minagi.store` surface
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
mkdir -p data/train/self-knowledge
printf '<user>\nhow do you decide which experts to use?\n</user>\n<bot>\nI route through a shared expert pool.\n</bot>\n' \
    > data/train/self-knowledge/self-0.txt
python3 train.py read data/train --passes 1 --sample-every 0.2 --minutes 2 --save
```

What to watch for in the output:

- `params ... | 64 experts | block-applications ...` — the pool is live.
- `sample log` entries (a `runs/samples.txt` section every 0.2 minutes,
  with raw and adapted readings per prompt lane, and an `<skills>` block
  when `--skills` is passed).
- `held-out loss` line — CPU is slow, so the number will be poor; the point
  is that the full read path executes end to end.

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
   pip install torch numpy pyyaml matplotlib flask chess
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

## Related docs

- [`docs/WORKFLOWS.md`](WORKFLOWS.md) — every app workflow in detail
- `README.md` → "Running the tests (sandboxed)" — what the test gate covers
- `artifacts/FINDINGS_INDEX.md` — the skill-supply-chain decision table and
  evidence locations
