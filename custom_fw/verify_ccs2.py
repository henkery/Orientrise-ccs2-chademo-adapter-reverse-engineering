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

    prefixes = ("ccs2_", "slac_", "sdp_", "cp_", "din_", "v2g_", "exi_")
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
    # din_session_init/step/start/get are driven by ccs2_init/ccs2_step/main; din_cd_req_encode_exi
    # is the autonomous CurrentDemandReq grammar encoder reached via the din_session default TX hook.
    for want in ("ccs2_init", "ccs2_step", "ccs2_rx", "ccs2_fill_current_ctrl", "ccs2_demand",
                 "slac_init", "slac_step", "sdp_init", "sdp_step", "cp_step", "cp_plug_in",
                 "din_scale", "din_cd_req_encode", "din_set_ev_target", "v2gtp_encode",
                 "din_session_init", "din_session_step", "din_session_start", "din_session_get",
                 "din_cd_req_encode_exi"):
        check(want in syms, "wired symbol present: " + want)
    # Live UDP/TCP/IPv6 + mbedTLS transport (v2g_net, Agent G/H / analyze94) wired into ccs2_init /
    # ccs2_step / ccs2_rx / main. The IPv6 RX path (ccs2_rx -> v2g_net_rx_ethernet -> deframe ->
    # exi_dispatch -> ccs2_rx_exi) now REACHES the EXI decode chain + session RX engine, so those
    # are no longer gc-eliminated — they are required-present here. The small helpers
    # (exi_dispatch/ipv6_linklocal/tls_decision/ip6_parse/ethertype) are -O2-INLINED into these
    # callers (no standalone symbol, like din_pow10); their LOGIC is verified via constants below.
    for want in ("v2g_net_init", "v2g_net_set_eth_send", "v2g_net_set_local_mac", "v2g_net_step",
                 "v2g_net_start_tcp", "v2g_net_rx_ethernet", "v2g_net_udp_send", "v2g_net_tcp_send",
                 "v2g_deframe_push", "v2g_net_trace_feed", "ccs2_rx_exi", "exi_decode_header",
                 "din_session_rx", "v2gtp_parse"):
        check(want in syms, "wired transport/RX symbol present: " + want)
    # din_pow10 is small + -O2-inlined into din_scale/current_ctrl_converter; its LOGIC is verified
    # below via the pow10 table blob (the analyze89 correction), not a standalone symbol.
    # The live transport RX path (v2g_net_rx_ethernet -> deframe -> exi_dispatch -> ccs2_rx_exi ->
    # exi_decode_header/din_session_rx) now FEEDS the EXI decode chain + session RX engine, so those
    # are required-present above. What remains bench-only (host-tested in test_ccs2/test_din70121/
    # test_din_session/test_v2g_net) and possibly --gc-sections-eliminated from the autonomous image:
    # the explicit flag setters + the grammar Res decoders they call + the bench-injected TCP
    # connected event. Report informationally (NOT failures). The EXI ENCODE path stays (autonomous
    # CurrentDemandReq via the TX hook + v2g_net_tcp_send).
    gated = ("din_cd_res_decode", "ccs2_currentdemand_res",
             "ccs2_cablecheck_done", "ccs2_chgparam_done", "ccs2_precharge_ready",
             "din_cd_res_decode_exi", "din_cablecheck_res_decode_exi",
             "din_precharge_res_decode_exi", "din_sessionstop_res_decode_exi",
             "v2g_net_tcp_connected")
    present_gated = [g for g in gated if g in syms]
    print("info: bench-only APIs gc-eliminated from autonomous image (host-tested): %s"
          % ", ".join(g for g in gated if g not in syms))
    print("info: bench-only APIs retained: %s" % (", ".join(present_gated) or "(none)"))

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
        for want in ("ccs2_init", "ccs2_step", "ccs2_fill_current_ctrl", "cp_step",
                     "din_session_get", "v2g_net_get", "v2g_net_tcp_send", "v2g_net_set_local_mac"):
            check(want in called, "main calls " + want)
        # ccs2_rx is wired via qca7005_set_rx_cb (function pointer), check it is referenced
        check("ccs2_rx_dispatch" in syms or "ccs2_rx" in called, "ccs2 RX dispatcher present")

    # --- pow10 table constants in din70121 (rodata pool) ---
    # scan the whole image for the consecutive pow10 table words
    tab = [1, 10, 100, 1000, 10000, 100000, 1000000]
    blob = b"".join(v.to_bytes(4, "little") for v in tab)
    check(blob in fw, "pow10 converter table {1..1000000} present in image")

    # --- session timer constants compiled into din_session (Agent F ctx init 0x08035198) ---
    # Collect every constant a function materializes: IMM operands + reconstructed MOVW/MOVT pairs
    # + dereferenced LDR-literal pool words (T1/T2). -O2 packs the ctx-init timeouts into a .rodata
    # pool (e.g. 120000=0x1D4C0, 150000=0x249F0 as words; 40000/14000 packed as the two u16 halves
    # of 0x36B09C40), so the pool words AND their low/high u16 halves are added (encoding-agnostic).
    def func_imms(name):
        addr = syms.get(name)
        if addr is None:
            return set()
        size = func_size(name)
        vals = set()
        movw = {}

        def add_word(w):
            vals.add(w & 0xFFFFFFFF)
            vals.add(w & 0xFFFF)          # packed u16 low half
            vals.add((w >> 16) & 0xFFFF)  # packed u16 high half

        for ins in md.disasm(fw[off(addr):off(addr) + size], addr):
            mn = ins.mnemonic.split(".")[0]
            for op in ins.operands:
                if op.type == 2:
                    vals.add(op.imm & 0xFFFFFFFF)
            if mn in ("movw", "movt") and len(ins.operands) == 2:
                rt = ins.operands[0].reg
                imm = ins.operands[1].imm & 0xFFFF
                if mn == "movw":
                    movw[rt] = imm
                    vals.add(imm)
                elif rt in movw:
                    vals.add((imm << 16) | movw[rt])
            h = int.from_bytes(ins.bytes[:2], "little")
            # LDR-literal T1: (h & 0xF800) == 0x4800
            if (h & 0xF800) == 0x4800:
                p = ((ins.address + 4) & ~3) + (h & 0xFF) * 4
                w = pool_word(p)
                if w is not None:
                    add_word(w)
            # LDR-literal T2 wide: (h & 0xFF7F) == 0xF85F
            if (h & 0xFF7F) == 0xF85F and len(ins.bytes) >= 4:
                u = (h >> 7) & 1
                imm12 = int.from_bytes(ins.bytes[2:4], "little") & 0xFFF
                p = (ins.address + 4) + (imm12 if u else -imm12)
                w = pool_word(p)
                if w is not None:
                    add_word(w)
        return vals

    init_imms = func_imms("din_session_init")
    timers = {4000: "resp-wait 4000ms", 120000: "total 120000ms", 150000: "150000ms",
              40000: "phase 40000ms", 14000: "phase 14000ms"}
    for v, label in timers.items():
        check(v in init_imms, "din_session_init carries timer constant " + label)
    step_imms = func_imms("din_session_step")
    check(20 in step_imms, "din_session_step carries retry cap 20 (cmp #0x14)")

    # -O2 inlines the small transport helpers into their (required-present) callers, so they have no
    # standalone symbol (like din_pow10). Verify their LOGIC via distinctive constants:
    #   ethertype()  -> v2g_net_rx_ethernet carries the IPv6 EtherType compare. The compiler emits a
    #                   ldrh LE + cmp #0xDD86 (the byte-swapped wire 0x86DD) — matching the stock
    #                   ethernet_input 0x0809D914 LE read; accept either the wire or LE-swapped form.
    #   ip6_parse()  -> v2g_net_rx_ethernet carries the next-header UDP 17 / TCP 6 demux
    #   exi_dispatch()-> ccs2_rx_exi present (above) proves it (only caller is deframe_cb)
    #   ipv6_linklocal()/tls_decision() -> inlined into set_local_mac/start_tcp (present above)
    rx_imms = func_imms("v2g_net_rx_ethernet")
    check(0x86DD in rx_imms or 0xDD86 in rx_imms,
          "v2g_net_rx_ethernet carries IPv6 EtherType 0x86DD/0xDD86 (ethertype inlined)")
    check(17 in rx_imms and 6 in rx_imms,
          "v2g_net_rx_ethernet carries next-header UDP 17 / TCP 6 (ip6_parse demux inlined)")
    # TLS config record (mbedTLS setup 0x080604D2): cipher list {0xC023,0xC025} + authmode 2 in init.
    net_init_imms = func_imms("v2g_net_init")
    check(0xC023 in net_init_imms and 0xC025 in net_init_imms,
          "v2g_net_init carries TLS cipher list {0xC023,0xC025}")

    print("%d checks, %d failures" % (checks, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())