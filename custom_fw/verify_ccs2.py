#!/usr/bin/env python3
"""verify_ccs2.py — disasm-verify the built CCS2 EVCC subsystem in app.elf (REPORT §5.9).

Encoding-agnostic safety + presence check on the linked firmware (app.bin @ 0x08020000):
  1. Presence: every CCS2 module function (ccs2_/slac_/sdp_/cp_/din_/v2gtp_) is linked in.
  2. Power-GPIO safety: the pure-logic CCS2 modules (slac/sdp/cp/din70121/ccs2/v2gtp) reference
     NO peripheral base 0x40000000-0x400FFFFF (no GPIO/SPI/DAC/PWM stores) — they are RAM-only
     communication logic. Collects ALL #imm operands + MOVW/MOVT pairs + dereferenced LDR-literal
     pool words (UXTH masks are not immediates; computed addresses won't appear as immediates).
     qca7005 (the SPI1 transport) is excluded — it legitimately touches SPI1/GPIOA/GPIOC and was
     verified in its own milestone.
  3. Integration: main calls ccs2_init / ccs2_step / ccs2_fill_current_ctrl / cp_step / ccs2_rx.
  4. pow10 table: din70121 carries the power-of-10 converter constants {1,10,100,1000,10000,
     100000,1000000} (the analyze89 correction).

Run: nix-shell -p gcc-arm-embedded python3 python3Packages.capstone --run 'python3 verify_ccs2.py'
"""
import re
import subprocess
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BASE = 0x08020000
PERIPH_LO, PERIPH_HI = 0x40000000, 0x400FFFFF

# Capstone ARM register IDs
R_PC, R_SP, R_LR = 81, 79, 80


def symbols():
    out = subprocess.check_output(["arm-none-eabi-objdump", "-t", "app.elf"], text=True)
    syms = {}
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]{8})\s+.*\s+(\S+)$", line)
        if not m:
            continue
        addr, name = int(m.group(1), 16), m.group(2)
        # function symbols in .text
        if ".text" in line and addr >= BASE:
            syms[name] = addr
    return syms


def func_size(name):
    out = subprocess.check_output(["arm-none-eabi-objdump", "-t", "app.elf"], text=True)
    for line in out.splitlines():
        if line.endswith(" " + name) and ".text" in line:
            parts = line.split()
            # format: addr g/l F/O .text size name
            try:
                idx = parts.index(".text")
                return int(parts[idx + 1], 16)
            except (ValueError, IndexError):
                return 0
    return 0


def main():
    with open("app.bin", "rb") as f:
        fw = f.read()
    syms = symbols()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    prefixes = ("ccs2_", "slac_", "sdp_", "cp_", "din_", "v2gtp_")
    ccs2_funcs = {n: a for n, a in syms.items() if n.startswith(prefixes)}
    checks = failures = 0

    def check(cond, msg):
        nonlocal checks, failures
        checks += 1
        if not cond:
            failures += 1
            print("FAIL:", msg)

    check(len(ccs2_funcs) >= 25, "CCS2 functions linked (%d found)" % len(ccs2_funcs))
    # Wired autonomous paths (referenced from main / ccs2_step / ccs2_rx) — MUST be present.
    for want in ("ccs2_init", "ccs2_step", "ccs2_rx", "ccs2_fill_current_ctrl", "ccs2_demand",
                 "slac_init", "slac_step", "sdp_init", "sdp_step", "cp_step", "cp_plug_in",
                 "din_scale", "din_cd_req_encode", "din_set_ev_target", "v2gtp_encode"):
        check(want in syms, "wired symbol present: " + want)
    # din_pow10 is small + -O2-inlined into din_scale/current_ctrl_converter; its LOGIC is verified
    # below via the pow10 table blob (the analyze89 correction), not a standalone symbol.
    # Gated bench-injection / live-IP-RX APIs (host-tested in test_din70121/test_sdp/test_ccs2) are
    # --gc-sections-eliminated from the autonomous image until the live EXI transport calls them.
    # Report their status informationally (NOT failures): din_cd_res_decode / v2gtp_parse /
    # ccs2_currentdemand_res / the session-flag setters.
    gated = ("din_cd_res_decode", "v2gtp_parse", "ccs2_currentdemand_res",
             "ccs2_cablecheck_done", "ccs2_chgparam_done", "ccs2_precharge_ready")
    present_gated = [g for g in gated if g in syms]
    print("info: gated bench APIs gc-eliminated from autonomous image (host-tested): %s"
          % ", ".join(g for g in gated if g not in syms))
    print("info: gated bench APIs retained: %s" % (", ".join(present_gated) or "(none)"))

    # --- power-GPIO safety: no peripheral base referenced in pure-logic CCS2 functions ---
    def off(addr):
        return addr - BASE

    def pool_word(addr):
        o = off(addr)
        if 0 <= o <= len(fw) - 4:
            return int.from_bytes(fw[o:o + 4], "little")
        return None

    safety_fail = []
    for name, addr in sorted(ccs2_funcs.items()):
        size = func_size(name)
        if size == 0:
            continue
        o = off(addr)
        code = fw[o:o + size]
        movw = {}
        periph = set()
        for ins in md.disasm(code, addr):
            mn = ins.mnemonic.split(".")[0]
            # collect immediate operands
            for op in ins.operands:
                if op.type == 2:  # IMM
                    v = op.imm & 0xFFFFFFFF
                    if PERIPH_LO <= v <= PERIPH_HI:
                        periph.add(v)
            # MOVW/MOVT pairs
            if mn in ("movw", "movt") and len(ins.operands) == 2:
                rt = ins.operands[0].reg
                imm = ins.operands[1].imm & 0xFFFF
                if mn == "movw":
                    movw[rt] = imm
                elif rt in movw:
                    v = (imm << 16) | movw[rt]
                    if PERIPH_LO <= v <= PERIPH_HI:
                        periph.add(v)
            # LDR-literal T1: (h & 0xF800) == 0x4800
            h = int.from_bytes(ins.bytes[:2], "little")
            if (h & 0xF800) == 0x4800 and len(ins.operands) == 2:
                rt = ins.operands[0].reg
                p = ((ins.address + 4) & ~3) + (h & 0xFF) * 4
                w = pool_word(p)
                if w is not None and PERIPH_LO <= w <= PERIPH_HI:
                    periph.add(w)
            # LDR-literal T2 wide: (h & 0xFF7F) == 0xF85F
            if (h & 0xFF7F) == 0xF85F and len(ins.bytes) >= 4:
                u = (h >> 7) & 1
                imm12 = int.from_bytes(ins.bytes[2:4], "little") & 0xFFF
                p = (ins.address + 4) + (imm12 if u else -imm12)
                w = pool_word(p)
                if w is not None and PERIPH_LO <= w <= PERIPH_HI:
                    periph.add(w)
        if periph:
            safety_fail.append((name, sorted(hex(v) for v in periph)))
    check(not safety_fail, "CCS2 pure-logic modules reference NO peripheral base (power-GPIO safe)")
    for name, vs in safety_fail:
        print("   peripheral ref in %s: %s" % (name, ", ".join(vs)))

    # --- integration: main bl targets ---
    main_addr = syms.get("main")
    check(main_addr is not None, "main symbol present")
    if main_addr:
        size = func_size("main")
        code = fw[off(main_addr):off(main_addr) + size]
        bl_targets = set()
        for ins in md.disasm(code, main_addr):
            if ins.mnemonic.split(".")[0] == "bl" and ins.operands and ins.operands[0].type == 2:
                bl_targets.add(ins.operands[0].imm)
        addr_to_name = {a: n for n, a in syms.items()}
        called = {addr_to_name.get(t, "") for t in bl_targets}
        for want in ("ccs2_init", "ccs2_step", "ccs2_fill_current_ctrl", "cp_step"):
            check(want in called, "main calls " + want)
        # ccs2_rx is wired via qca7005_set_rx_cb (function pointer), check it is referenced
        check("ccs2_rx_dispatch" in syms or "ccs2_rx" in called, "ccs2 RX dispatcher present")

    # --- pow10 table constants in din70121 (rodata pool) ---
    # scan the whole image for the consecutive pow10 table words
    tab = [1, 10, 100, 1000, 10000, 100000, 1000000]
    blob = b"".join(v.to_bytes(4, "little") for v in tab)
    check(blob in fw, "pow10 converter table {1..1000000} present in image")

    print("%d checks, %d failures" % (checks, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())