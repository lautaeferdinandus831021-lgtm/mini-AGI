#!/usr/bin/env python3
"""
Targeted tests for the app's most recent fixes. Run by scripts/test_sandbox.sh
inside a throwaway checkout, or by hand from the repo root:

    python3 tests/test_targeted.py

What is covered, and which change each test pins down:

  1. serve.py identity wiring   the page is rendered from minagi/identity.py
                                (no hardcoded app name anywhere), and every
                                route answers without a model loaded.
                                Pins PR #11; needs flask+torch, skips cleanly
                                without them.

  2. incremental UTF-8 decode   the SSE stream emits whole characters, not
                                bytes - the exact algorithm serve.stream() uses,
                                exercised on ASCII / Latin-1 / CJK / emoji, with
                                the old byte-at-a-time behaviour shown wrong on
                                every non-ASCII case, and an invalid byte
                                degrading to U+FFFD instead of crashing.
                                Pins PR #11. Pure stdlib, always runs.

  3. train.py growth-line print the pool growth/prune progress line prints on
                                every platform: the CUDA ternary is bound to the
                                vram suffix only, never to the print itself. The
                                shipped block is exec'd twice - a CPU
                                environment whose fake torch.cuda raises if
                                touched, and a CUDA environment asserting the
                                vram figure appears. Pins PR #12. Always runs.

  4. minagi/stream invariants  the reader hands the model pos_offset == seen
                                (the rotary alignment invariant), targets are
                                inputs shifted by one, the window resets before
                                running past the context; trim keeps the newest
                                cache positions and detach drops the graph;
                                ramp_context is monotone, bounded and lands on
                                `end` at the warm fraction. Needs torch, skips
                                cleanly without it.

  5. minagi/paged contracts    Tiers LRU eviction and dirty writeback (weights
                                fp32, moments as bf16 bits, read-only never
                                writes); PagedPool.dying() staleness math with
                                its trial waiver and age clamp; swap_to keeps
                                residents in their slots by identity; growth
                                names files by uid and prune deletes by
                                staleness WITHOUT renumbering the survivors.
                                Needs torch, skips cleanly without it.

  6. minagi/live (LiveLearner)  the stream steps every `chunk` characters
                                with pending accounting that survives partial
                                feeds; the model is called on inputs/targets
                                shifted by one; buf never exceeds `context`;
                                the model's train/eval mode survives a step;
                                grads are cleared even when a step fails; and
                                save() carries the loaded manifest (step/val)
                                through instead of writing a blank one - the
                                vocab-8192-manifest bug the module documents.
                                Needs torch, skips cleanly without it.

  7. minagi/plasticity          the rate moves in BOTH directions - easing
                                down without evidence, back up when held-out
                                improves - but only past MIN_EFF; a regime jump
                                must persist to confirm and resets the fits;
                                noise and non-finite evaluations change
                                nothing; scale stays inside [FLOOR, CEIL];
                                state() round-trips through restore(), which
                                also replays legacy hist checkpoints. Pure
                                stdlib, always runs.

  8. minagi/knowledge           the report-knowledge store: records validate
                                hard at save time (required fields, status /
                                report_type enums, date and id formats,
                                timeline/evidence shapes), writes are atomic
                                tmp+rename and never overwrite silently,
                                list/search/timeline answer questions over the
                                store (conjunctive keyword search, status and
                                target filters, newest-first timeline), and
                                to_markdown() renders the triager-readable
                                report back out. Pure stdlib, always runs.

Exit code 0 iff no check failed. Sections that cannot run in this environment
print SKIP lines and count as neither pass nor failure.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PASS = 0
FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print(f"  PASS {name}")


def bad(name, why=""):
    global FAIL
    FAIL += 1
    print(f"  FAIL {name}" + (f" - {why}" if why else ""))


def check(cond, name, why=""):
    ok(name) if cond else bad(name, why)


# ---------------------------------------------------------------------------
print("== 1. serve.py identity wiring (PR #11) ==")
try:
    import serve
except Exception as e:                                   # no flask/torch here
    print(f"  SKIP serve.py identity + routes ({type(e).__name__}: {e})")
    serve = None

if serve is not None:
    check("@@APP_NAME@@" not in serve.PAGE,
          "PAGE fully rendered from identity.py")
    check("<title>WhiteHat_mini-AGI</title>" in serve.PAGE,
          "<title> carries the identity name")
    check("const APP_NAME = 'WhiteHat_mini-AGI'" in serve.PAGE,
          "JS APP_NAME constant carries the identity name")
    check(serve._APP_NAME == "WhiteHat_mini-AGI",
          "_APP_NAME imported from minagi.identity")
    check(hasattr(serve, "stream"), "serve module exposes stream()")

    client = serve.app.test_client()
    r = client.get("/")
    check(r.status_code == 200 and b"WhiteHat_mini-AGI" in r.data,
          "GET / renders 200 + identity")
    r = client.get("/api/skills")
    j = r.get_json()
    check(r.status_code == 200 and "security" in j["groups"],
          "GET /api/skills lists groups")
    r = client.get("/api/skills?name=IS_JSON&text=%7B%22a%22%3A1%7D")
    check(r.status_code == 200 and r.get_json()["result"] is True,
          "GET /api/skills?name=IS_JSON single-skill run")
    r = client.get("/api/state")
    check(r.status_code == 200 and "reselect" in r.get_json(),
          "GET /api/state without a loaded model")
    r = client.get("/api/prime")
    check(r.status_code == 200 and "chars" in r.get_json(),
          "GET /api/prime")

# ---------------------------------------------------------------------------
print("== 2. incremental UTF-8 decode (PR #11 regression) ==")
import codecs


def old_emit(byts):
    """The pre-#11 behaviour: one byte -> one decode."""
    return "".join(bytes([b]).decode("utf-8", "replace") for b in byts)


def new_emit(byts):
    """Exactly what serve.stream() does per step, replayed here."""
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    return "".join(p for b in byts for p in [dec.decode(bytes([b]))] if p)


CASES = {"ascii": "hello", "latin-1": "naïve café", "cjk": "你好",
         "emoji": "hi \U0001F680!", "greek": "αβγ",
         "mixed": "aé你\U0001F680z"}
for name, text in CASES.items():
    byts = list(text.encode("utf-8"))
    check(new_emit(byts) == text,
          f"decode round-trip exact: {name}", f"got {new_emit(byts)!r}")
    if old_emit(byts) != text:
        ok(f"  (old path was wrong for {name} - regression confirmed)")

dec = codecs.getincrementaldecoder("utf-8")("replace")
pieces = [p for b in [0xFF, 0x41] for p in [dec.decode(bytes([b]))] if p]
check("".join(pieces) == "\ufffdA",
      "invalid byte degrades to U+FFFD without crashing")

# ---------------------------------------------------------------------------
print("== 3. train.py growth-line print (PR #12) ==")
with open(os.path.join(ROOT, "train.py")) as f:
    src = f.read()

m = re.search(r'vram = \(f"vram ".*?flush=True\)', src, re.S)
check(m is not None, "growth-line block (vram assignment + print) found")
if m:
    # the block sits 24 columns deep inside cmd_read; strip exactly that
    # indent (textwrap.dedent cannot: the regex starts mid-line)
    block = re.sub(r"\n {24}", "\n", m.group(0))
    check(re.search(r'print\(.*if device\.type == "cuda" else ""\)',
                    block, re.S) is None,
          "no ternary wraps the print itself")

    def _env(device_type, cuda_fn):
        import types
        return {
            "pool": types.SimpleNamespace(n_experts=lambda: 65,
                                          vram_params=lambda: 25.2e6),
            "rec": {"grew": 1}, "gone": 0,
            "torch": types.SimpleNamespace(cuda=types.SimpleNamespace(
                max_memory_allocated=cuda_fn)),
            "device": types.SimpleNamespace(type=device_type),
        }

    # CPU branch: torch.cuda must not be touched at all
    def _boom():
        raise AssertionError("cuda touched on the CPU branch")
    out = []
    env = _env("cpu", _boom)
    env["print"] = lambda *a, **k: out.append(a[0])
    exec(compile(block, "<growth-line>", "exec"), env)
    cpu_line = out[-1]
    check("pool 65 experts (+1)" in cpu_line,
          "CPU branch prints the growth line", f"got {cpu_line!r}")
    check("vram" not in cpu_line, "CPU branch carries no vram figure")

    # CUDA branch: the line and the vram figure both appear
    out2 = []
    env_cuda = _env("cuda", lambda: 8_000_000_000)
    env_cuda["print"] = lambda *a, **k: out2.append(a[0])
    exec(compile(block, "<growth-line>", "exec"), env_cuda)
    cuda_line = out2[-1]
    check("pool 65 experts (+1)" in cuda_line and "8000MB" in cuda_line,
          "CUDA branch prints growth line + vram", f"got {cuda_line!r}")

check(re.search(r"'-%d' % gone if gone else ''", src) is not None,
      "prune (-N) variant still wired")

# ---------------------------------------------------------------------------
try:
    import torch
except ImportError:
    torch = None

print("== 4. minagi/stream invariants ==")
if torch is None:
    print("  SKIP minagi/stream (torch not installed)")
else:
    import types

    import numpy as np

    from minagi import stream as mstream

    BLOCK, CHUNK, NSLOT = 64, 16, 3

    class FakeModel:
        """The only surface Reader touches: empty_caches, cfg.block, and a
        forward that reports the pos_offset it was handed."""

        def __init__(self):
            self.cfg = types.SimpleNamespace(block=BLOCK)
            self.saw = []
            self.caches_seen = []

        def empty_caches(self):
            return [{"k": None, "v": None} for _ in range(NSLOT)]

        def __call__(self, x, y, caches=None, pos_offset=0):
            self.saw.append(pos_offset)
            self.caches_seen.append(caches)
            for c in caches or []:
                # k and v are always written as a pair - that is the
                # contract Attention.forward maintains, and detach_caches /
                # trim_caches rely on it
                c["k"] = torch.zeros(1, 1, pos_offset + x.shape[1], 2)
                c["v"] = torch.zeros(1, 1, pos_offset + x.shape[1], 2)
            return None, float(pos_offset) + float(x.float().mean())

    data = np.arange(200, dtype=np.int64)

    r = mstream.Reader(FakeModel(), data, "t", CHUNK, BLOCK, "cpu")
    r.pos = 0
    x, y = r.next_chunk()
    check(torch.equal(x, torch.from_numpy(data[:CHUNK]).unsqueeze(0)),
          "next_chunk x = data[pos:pos+chunk]")
    check(torch.equal(y, torch.from_numpy(data[1:CHUNK + 1]).unsqueeze(0)),
          "targets are the inputs shifted by one")

    model = FakeModel()
    r = mstream.Reader(model, data, "t", CHUNK, BLOCK, "cpu")
    for _ in range(5):
        r.step(learn=False)
    check(model.saw == [0, CHUNK, 2 * CHUNK, 3 * CHUNK, 0],
          "pos_offset counts from 0 wherever the corpus window starts, "
          "and resets before the tables end",
          f"got {model.saw}")
    check(r.seen == CHUNK, "seen restarts with the new window")
    check(model.caches_seen[0] is model.caches_seen[3],
          "one cache carries across the chunks of a window")
    check(model.caches_seen[4] is not model.caches_seen[0],
          "reset builds a fresh cache for the next window")

    k = torch.arange(10, dtype=torch.float32).view(1, 1, 10, 1) \
        .expand(1, 1, 10, 4).contiguous()
    caches = [{"k": k, "v": torch.zeros(1, 1, 10, 4)}]
    mstream.trim_caches(caches, 4)
    check(caches[0]["k"].shape[-2] == 4,
          "trim_caches keeps `keep` positions")
    check(torch.equal(caches[0]["k"][0, 0, :, 0],
                      torch.tensor([6., 7., 8., 9.])),
          "trim keeps the NEWEST positions, not the oldest")
    short = [{"k": torch.zeros(1, 1, 6, 4), "v": torch.zeros(1, 1, 6, 4)}]
    mstream.trim_caches(short, 10)
    check(short[0]["k"].shape[-2] == 6,
          "trim_caches never pads a short cache")

    base = torch.randn(2, 2, 3, 4, requires_grad=True)
    caches = [{"k": base * 2, "v": base * 3}]
    check(caches[0]["k"].grad_fn is not None,
          "a cache entry carries the graph before detach")
    mstream.detach_caches(caches)
    check(caches[0]["k"].grad_fn is None and not caches[0]["k"].requires_grad,
          "detach_caches drops the autograd graph, keeps the values")

    rc = mstream.ramp_context
    check(rc(0, 1000, 512, 4096) >= 512, "ramp starts at the floor")
    check(rc(1000, 1000, 512, 4096) == 4096,
          "ramp lands on end once the warm fraction has passed")
    vals = [rc(s, 1000, 512, 4096) for s in range(0, 1001, 50)]
    check(all(b >= a for a, b in zip(vals, vals[1:])), "ramp is monotone")
    check(all(512 <= v <= 4096 for v in vals), "ramp stays bounded")
    check(all(v % 256 == 0 for v in vals),
          "ramp honours the granularity (no staircase-free jumps)")
    check(rc(10, 1000, 512, 100) == 100,
          "end <= start degenerates to end")

# ---------------------------------------------------------------------------
print("== 5. minagi/paged contracts ==")
if torch is None:
    print("  SKIP minagi/paged (torch not installed)")
else:
    import tempfile

    import numpy as _np

    from minagi.paged import PagedPool, Tiers
    from minagi.precision import unpack_bf16


    def _ent(i):
        return {"w1": torch.full((16, 8), float(i)),
                "w3": torch.full((16, 8), float(i)),
                "w2": torch.full((8, 16), float(i))}


    tiers_path = tempfile.mkdtemp(prefix="pp-tiers-")
    t = Tiers(tiers_path, 8, 16, ram_capacity=2, device="cpu")
    for i in range(4):
        t.put(i, _ent(i), dirty=True)
    check(len(t.ram) == 2 and set(t.ram) == {2, 3},
          "LRU holds only ram_capacity entries, newest kept")
    check(t.evictions == 2 and t.writebacks == 2,
          "evicted dirty entries are written back")
    z = _np.load(os.path.join(tiers_path, "e00000.npz"))
    check(z["w1"].dtype == _np.float32, "weights write back fp32")
    got = t.fetch(0)
    check(float(got["w1"][0, 0]) == 0.0,
          "a fetched entry is the one that was put")
    t.fetch(3)
    check(t.hits == 1, "fetch of a cached entry counts a hit")
    t.put(4, _ent(4), dirty=True)
    check(set(t.ram) == {3, 4},
          "fetch refreshes recency: the stale entry is evicted, not the fresh one")

    e = _ent(7)
    e["w1_m"] = torch.randn(16, 8)
    t.put(7, e, dirty=True)
    t.put(8, _ent(8), dirty=True)     # evicts 4
    t.put(9, _ent(9), dirty=True)     # evicts 7 -> writes it back
    z = _np.load(os.path.join(tiers_path, "e00007.npz"))
    check(z["w1_m"].dtype == _np.int16, "Adam moments write back as bf16 bits")
    back = unpack_bf16(z["w1_m"])
    check(torch.allclose(back, e["w1_m"], rtol=0.01, atol=0.02),
          "bf16 moment round-trip stays within its own rounding")

    ro_path = tempfile.mkdtemp(prefix="pp-ro-")
    ro = Tiers(ro_path, 8, 16, ram_capacity=1, device="cpu", read_only=True)
    ro.put(0, _ent(0), dirty=True)
    ro.flush()
    check(not ro.dirty and not os.path.exists(os.path.join(ro_path, "e00000.npz")),
          "read-only tiers never mark dirty and never write")

    pool_path = tempfile.mkdtemp(prefix="pp-pool-")
    for i in range(6):
        _np.savez(os.path.join(pool_path, "e%05d.npz" % i), **_ent(i))
    pp = PagedPool(pool_path, d_model=8, d_ff=16, n_experts=6,
                   resident=4, ram_capacity=8, device="cpu")
    check(pp.n_experts() == 6 and pp.n_routable() == 4,
          "n_experts answers the pool, n_routable the working set")
    pp.segments = 100
    pp.now = 1000
    pp.trial = 400
    d = pp.dying()
    check(torch.isclose(d, torch.full((6,), 2.5)).all(),
          "dying() = time unaddressed over the survival window")
    pp.born[5] = 800
    check(float(pp.dying()[5]) == 0.0,
          "an expert inside its trial is not dying")
    pp.born[5] = 590                 # 410 steps old: past the trial, barely
    check(torch.isclose(pp.dying()[5], torch.tensor(1.025)),
          "a barely-admissible expert is capped by its own age, not scored "
          "as if it had never been seen")
    fresh = PagedPool(tempfile.mkdtemp(prefix="pp-fresh-"), d_model=8,
                      d_ff=16, n_experts=6, resident=2, device="cpu")
    check(bool((fresh.dying() == 0).all()),
          "dying() is all zeros before the run starts")

    pp3 = PagedPool(pool_path, d_model=8, d_ff=16, n_experts=6,
                    resident=3, ram_capacity=8, device="cpu")
    pp3.swap_to([2, 0, 1])
    check(pp3.slots == [2, 0, 1], "swap_to places the requested set")
    check(pp3.swap_to([1, 0, 2]) == 0 and pp3.slots == [2, 0, 1],
          "the same set in a new order is a no-op (slots belong to experts)")
    loads = pp3.swap_to([3, 0, 1])
    check(pp3.slots == [3, 0, 1], "only the newcomer changes slots")
    check(loads == 1, "exactly one expert is fetched from the host")
    check(pp3.swaps == 2, "the no-op reorder did not count as a swap")

    n0 = pp3.n_experts()
    pp3.add_experts(2, recombine=3, step=10, birth_gate=0.01)
    uids = pp3.uid.tolist()
    check(pp3.n_experts() == n0 + 2, "add_experts grows the pool")
    check(len(set(uids)) == pp3.n_experts(), "every expert keeps a unique uid")
    check(max(uids) == n0 + 1, "new experts are named by fresh uids, not positions")
    check(pp3.segment_router.weight.shape[0] == pp3.n_experts(),
          "the segment router gains a row per expert")
    check(bool((pp3.gate[n0:] == 0.01).all()), "newcomers are born at birth_gate")
    files = os.listdir(pool_path)
    check(f"e{uids[n0]:05d}.npz" in files and f"e{uids[n0 + 1]:05d}.npz" in files,
          "growth writes one file per new expert, named by uid")

    before = uids
    # last_seen is already right: every swap_to stamps the requested set with
    # the segment it ran in (even the no-op reorder), so positions 0-3 read as
    # just-asked and 4-7 as never-chosen. Window = survival x segments/step =
    # 300 x 3/1000 = 0.9 segments - shorter than any non-resident's gap.
    target_uid = before[4]
    gone = pp3.prune(1000, survival=300)
    check(gone == 5 and pp3.n_experts() == 3,
          "prune removes exactly the stale, non-resident experts")
    after = pp3.uid.tolist()
    check(target_uid not in after, "the stale expert is gone")
    check(after == [u for u in before if u in after],
          "survivors keep their uid AND their order (nothing renumbered)")
    check(not os.path.exists(os.path.join(pool_path, f"e{target_uid:05d}.npz")),
          "the deleted expert's file goes with it")
    check(pp3.segment_router.weight.shape[0] == pp3.n_experts(),
          "the segment router is rebuilt to the surviving count")

# ---------------------------------------------------------------------------
print("== 6. minagi/live (LiveLearner) ==")
if torch is None:
    print("  SKIP minagi/live (torch not installed)")
else:
    import tempfile
    import types
    import json as _json

    from minagi.live import LiveLearner, exchange_text
    from minagi.tokenizer import ByteTokenizer

    tok = ByteTokenizer()

    check(exchange_text(" hi ", " yo ") ==
          "<user>\nhi\n</user>\n<bot>\nyo\n</bot>\n",
          "exchange_text marks one turn the way the chat corpus is")
    check(exchange_text("", "") == "", "an empty exchange is an empty string")

    class TinyModel(torch.nn.Module):
        """The surface LiveLearner actually uses, plus a pool.* parameter:
        the optimiser is built with a trunk group and a pool group, and a
        model without any pool-prefixed parameter would hand AdamW an empty
        group."""

        def __init__(self):
            super().__init__()
            self.cfg = types.SimpleNamespace(block=64, vocab_size=265)
            self.calls = []
            self.emb = torch.nn.Embedding(265, 8)
            self.head = torch.nn.Linear(8, 265)
            self.pool = torch.nn.Module()
            self.pool.dummy = torch.nn.Parameter(torch.zeros(1))

        def forward(self, x, y=None, caches=None, pos_offset=0):
            self.calls.append((x.shape[1], y.shape[1]))
            logits = self.head(self.emb(x))
            loss = torch.nn.functional.cross_entropy(
                logits.reshape(-1, 265), y.reshape(-1))
            return logits, loss

    tmp = tempfile.mkdtemp(prefix="live-")
    m = TinyModel()
    ll = LiveLearner(m, lr=1e-3, chunk=40, context=64, save_every=100,
                     weights_dir=os.path.join(tmp, "w"),
                     manifest={"step": 7, "val": 0.5,
                               "cfg": {"vocab_size": 265, "block": 64}})

    recs = ll.feed("x" * 30, tok)
    check(recs == [] and ll.pending == 30,
          "a partial feed takes no step and reports pending")
    recs = ll.feed("y" * 30, tok)
    check(len(recs) == 1 and ll.pending == 20 and ll.steps == 1,
          "crossing `chunk` takes exactly one step and keeps the remainder")
    check(m.calls[0] == (39, 39),
          "the model is called on targets = inputs shifted by one (x = buf[:-1])")
    ll.feed("z" * 60, tok)
    check(m.calls[-1][0] == 63,
          "the window caps at `context` (buf trimmed before the step)")
    check(ll.steps == len(ll.log), "every step is logged once")

    m.eval()
    ll.feed("w" * 40, tok)
    check(not m.training, "a step taken from eval mode returns the model to eval")
    m.train()
    ll.feed("w" * 40, tok)
    check(m.training, "a step taken mid-training leaves training on")
    check(all(p.grad is None for p in m.parameters()),
          "grads are cleared after every step, success or not")

    class Boom(TinyModel):
        def forward(self, *a, **k):
            raise RuntimeError("boom")

    ll2 = LiveLearner(Boom(), chunk=10, context=64,
                      weights_dir=os.path.join(tmp, "w2"))
    raised = False
    try:
        ll2.feed("q" * 12, tok)
    except RuntimeError:
        raised = True
    check(raised, "a failing model surfaces the error (serve catches it)")
    check(ll2.pending == 10,
          "the failed step leaves the stream at its boundary, unreset")
    check(all(pg.grad is None for pg in ll2.model.parameters()),
          "grads are cleared even when the step itself fails (zero_grad "
          "lives in a finally)")

    ll.save()
    man = _json.load(open(os.path.join(tmp, "w", "manifest.json")))
    check(man.get("step") == 7 and man.get("val") == 0.5,
          "save() carries the loaded manifest's step/val through")
    check(man.get("cfg", {}).get("vocab_size") == 265,
          "save() carries the manifest cfg through (no blank 8192 manifest)")
    check(ll.unsaved == 0 and not ll.due_to_save(),
          "save() resets the unsaved counter")

# ---------------------------------------------------------------------------
print("== 7. minagi/plasticity rules ==")
from minagi.plasticity import Plasticity

# warmup: the rate eases in over the first WARMUP optimiser steps
p = Plasticity()
for _ in range(10):
    p.tick()
check(p.factor() < 1.0, "warmup scales the rate up gradually")
p2 = Plasticity()
for _ in range(Plasticity.WARMUP + 1):
    p2.tick()
check(p2.factor() == 1.0, "past warmup the factor is the full rate")

# plateau: below MIN_EFF nothing moves, however bad it looks
p = Plasticity()
for _ in range(5):
    p.observe(0.5, 0.01)
check(p.scale == 1.0, "below MIN_EFF the rate does not move at all")
check(p.i == 5.0, "the evaluations were still recorded")

# easing DOWN: held-out stuck above the neutral point nudges the rate down,
# but only once the slow fit has MIN_EFF effective observations
p = Plasticity()
for _ in range(int(Plasticity.MIN_EFF) + 4):
    p.observe(0.5, 0.01)
check(p.scale < 1.0,
      "a flat held-out eases the rate down once there is enough evidence")
check(p.scale >= Plasticity.FLOOR, "the rate never sinks below FLOOR")

# easing UP: held-out steadily improving, confirmed by the fast fit, lifts a
# dragged-down rate back toward CEIL. CEIL is 1.0, so from a fresh instance
# the only visible direction is down - start from a lowered scale instead.
# A perfectly straight series has no residual (sigma = 0), which the fit
# reports as no verdict - so the series carries a sliver of scatter.
p = Plasticity.restore({"scale": 0.5})
for i in range(60):
    p.observe(0.8 - 0.01 * i + 0.0003 * (i % 2), 0.001)
check(p.scale > 0.5,
      "clear, sustained improvement eases the rate up (the two rules are "
      "symmetric)")
check(p.scale <= Plasticity.CEIL, "the rate never exceeds CEIL")

# the fast fit can veto the slow one before it has enough observations
# (MIN_EFF gates the cap only, so this is about the verdict, not the veto)
p = Plasticity()
check(p._verdict()[0] == 0.0, "an empty fit has no verdict")

# a REGIME JUMP must persist one evaluation to confirm, then resets both fits
p = Plasticity()
for _ in range(20):
    p.observe(0.5, 0.001)
check(p.scale < 1.0, "plateau eased the rate down before the jump")
p.observe(2.0, 0.001)                 # candidate jump: nominated, not confirmed
check(p.jump_from == 0.5 and p.scale < Plasticity.CEIL,
      "a single noisy evaluation only nominates a regime change")
note = p.observe(2.0, 0.001)          # persisted: confirmed
check(note is not None and p.scale == Plasticity.CEIL and "regime" in note,
      "a persistent jump steps the rate back up and says so")
check(p.i == 1.0, "the confirming evaluation is the first in the new fit")
check(p.jump_from is None, "a confirmed jump consumes its own nomination")
p.observe(0.4, 0.001)                 # fell straight back: nothing pending
check(p.jump_from is None, "a fall straight back nominates nothing")

# noise hygiene: missing se and non-finite values change nothing
p = Plasticity()
for _ in range(30):
    p.observe(0.5, None)
check(len(p.se_hist) == 0 and p._se() == 0.0,
      "an evaluation with no stated error leaves no noise history")
check(p.i == 30.0, "evaluations without an error still count toward the fits")
p.observe(0.5, 0.01)                  # seed the noise history
check(p.observe(float("nan"), 0.01) is None and p.prev == 0.5
      and p.i == 31.0,
      "a non-finite evaluation is ignored entirely")
check(p.observe(float("inf"), 0.01) is None and p.prev == 0.5,
      "so is a non-finite one the other way")

# checkpoint round-trip, including the legacy hist replay
p = Plasticity()
for _ in range(25):
    p.observe(0.5 - 0.001 * _, 0.01)
snap = p.state()
q = Plasticity.restore(snap)
check(q.scale == p.scale and q.i == p.i and q.step == p.step and
      len(q.se_hist) == len(p.se_hist),
      "state() round-trips through restore()")
legacy = Plasticity.restore({"hist": [1.0] * 20, "scale": 0.5, "step": 9})
check(legacy.scale == 0.5 and legacy.i == 20.0 and legacy.step == 9,
      "restore() replays a legacy hist checkpoint")
check("rate x" in Plasticity().describe(), "describe() reports the rate")

# ---------------------------------------------------------------------------
print("== 8. minagi/knowledge store ==")
import tempfile as _td

_kd = os.path.join(_td.mkdtemp(prefix="know-"), "records")
os.environ["KNOWLEDGE_DIR"] = _kd
import importlib
import minagi.knowledge as kn
importlib.reload(kn)          # pick up the KNOWLEDGE_DIR set above

BASE = {
    "id": "demo-a", "title": "A demo report", "program": "prog", "target": "t",
    "report_type": "verification", "status": "draft", "severity": "none",
    "summary": "what happened and why it matters",
    "cwe": ["CWE-416"], "date_filed": "2026-09-01", "date_closed": "",
    "timeline": [{"date": "2026-09-01", "event": "filed"}],
    "key_facts": ["the fact"], "evidence": [{"path": "e/", "note": "n"}],
    "commands": [], "lessons": [], "references": [], "related": [],
}

check(kn.validate(dict(BASE)) is not None,
      "a complete record validates")
for field, bad in [("status", "closed"), ("report_type", "other"),
                   ("date_filed", "Sept 1"), ("id", "Bad Slug")]:
    r = dict(BASE)
    r[field] = bad
    try:
        kn.validate(r)
        check(False, f"bad {field} rejected")
    except kn.RecordError:
        check(True, f"bad {field} rejected")
r = dict(BASE)
del r["key_facts"]
try:
    kn.validate(r)
    check(False, "a missing required field is rejected")
except kn.RecordError:
    check(True, "a missing required field is rejected")
r = dict(BASE)
r["timeline"] = [{"date": "2026-09-01"}]
try:
    kn.validate(r)
    check(False, "a timeline entry without an event is rejected")
except kn.RecordError:
    check(True, "a timeline entry without an event is rejected")

kn.save(dict(BASE))
try:
    kn.save(dict(BASE))
    check(False, "save never overwrites silently")
except kn.RecordError:
    check(True, "save never overwrites silently")
check(os.path.exists(os.path.join(_kd, "demo-a.json"))
      and not os.path.exists(os.path.join(_kd, "demo-a.json.tmp")),
      "the atomic write leaves the record, never the tmp file")

second = dict(BASE, id="demo-b", status="resolved", date_filed="2026-08-01",
              title="An older resolved one",
              timeline=[{"date": "2026-08-01", "event": "older event"}],
              key_facts=["nothing to see here"])
kn.save(second)
check([r["id"] for r in kn.list_records()] == ["demo-b", "demo-a"],
      "list sorts by date_filed, undated last")
check([r["id"] for r in kn.list_records(status="resolved")] == ["demo-b"],
      "the status filter answers 'what is still open'")
check(kn.search("demo") and not kn.search("demo", status="withdrawn"),
      "search ANDs keywords with the status filter")
check([e["id"] for e in kn.timeline()][:1] == ["demo-a"],
      "the merged timeline runs newest-first")
check(kn.stats()["records"] == 2, "stats counts the store")
md = kn.to_markdown(kn.load("demo-a"))
check("# A demo report" in md and "CWE-416" in md and "## Timeline" in md,
      "to_markdown renders the triager-readable report")
kn.save(dict(BASE, id="demo-a", title="replaced on purpose"), overwrite=True)
check(kn.load("demo-a")["title"] == "replaced on purpose",
      "overwrite=True replaces an existing record on purpose")

# ---------------------------------------------------------------------------
print()
print(f"[result] PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
