#!/usr/bin/env python3
"""run_host_tests.py — build + run every custom_fw host unit test (test_*.c) and aggregate checks.

Each test carries its own gcc build command in its header comment. This extracts that command
(`gcc ... && ./test_X`), strips the C-comment framing (leading ` * ` markers + `\\` continuations),
unescapes `\\"`, and runs it via bash (so the mbedTLS `library/*.c` wildcard expands). Run under
nix-shell so gcc is on PATH:

  nix-shell -p gcc --run 'python3 run_host_tests.py'

Exits non-zero if any test fails to build/run or reports failures. Pure-logic replicas only — no
hardware; the firmware build + verify_ccs2.py cover the hardware-linked image separately.
"""
import glob
import os
import re
import subprocess
import sys


def extract_cmd(path):
    stem = os.path.basename(path)[:-2]  # test_X
    head = open(path, encoding="utf-8", errors="replace").read()[:2500]
    # Match the compiler invocation 'gcc -O2/-Isrc/-w ...', NOT the 'gcc --run' in the nix-shell
    # wrapper (the (?!--) lookahead skips it so we don't capture the wrapper's stray quote).
    m = re.search(r"(gcc\s+(?!--).+?&&\s*\./" + re.escape(stem) + r")", head, re.S)
    if not m:
        return None
    cleaned = []
    for ln in m.group(1).split("\n"):
        ln = ln.rstrip()
        if ln.endswith("\\"):
            ln = ln[:-1]
        ln = re.sub(r"^\s*/?\*+\s?", "", ln)   # strip leading comment marker
        cleaned.append(ln.strip())
    # The header writes \" for a literal double-quote gcc must receive (e.g. the mbedTLS
    # -DMBEDTLS_CONFIG_FILE="..."). Wrap it in single quotes so bash passes the quotes through.
    cmd = " ".join(cleaned).replace('\\"', "'\"'")
    return re.sub(r"\s+", " ", cmd).strip()


def main():
    tests = sorted(glob.glob("test_*.c"))
    total_checks = total_fail = 0
    failed = []
    for t in tests:
        stem = t[:-2]
        cmd = extract_cmd(t)
        if not cmd:
            print(f"[SKIP] {stem}: no build command found in header")
            failed.append(stem + "(no-cmd)")
            continue
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
        out = r.stdout + r.stderr
        m = re.search(r"(\d+)\s+checks,\s+(\d+)\s+failures", out)
        if r.returncode != 0 or not m:
            print(f"[FAIL] {stem}: rc={r.returncode}")
            print(out[-1500:])
            failed.append(stem)
            continue
        checks, fails = int(m.group(1)), int(m.group(2))
        total_checks += checks
        total_fail += fails
        print(f"[{'ok' if fails == 0 else 'FAIL'}] {stem}: {checks} checks, {fails} failures")
        if fails:
            failed.append(stem)
    print(f"\nTOTAL: {total_checks} checks, {total_fail} failures across {len(tests)} tests")
    if failed:
        print("failed:", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()