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
print()
print(f"[result] PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
