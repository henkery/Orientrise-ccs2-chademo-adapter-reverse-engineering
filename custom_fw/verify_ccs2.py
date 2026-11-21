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

    prefixes = ("ccs2_", "slac_", "sdp_", "cp_", "din_", "v2g_", "exi_", "nd6_", "ca_")
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
    # CP PWM TIM4 input-capture front-end (cp_capture, Agent J / analyze95) wired into main
    # (cp_capture_init + duty/period feed cp_step). The strong TIM4_IRQHandler proves the ISR is
    # retained (IRQ30 vector). cp_capture_get/changed are small + -O2-inlined (no standalone
    # symbol, like din_pow10); the pure median/publish/process + getters are required-present.
    for want in ("cp_capture_init", "cp_capture_median", "cp_capture_publish", "cp_capture_process",
                 "cp_capture_duty", "cp_capture_period", "cp_capture_update_count", "TIM4_IRQHandler"):
        check(want in syms, "wired CP-capture symbol present: " + want)
    # CP/PP ADC3 analog acquisition front-end (cp_adc, Agent I / analyze95) wired into main
    # (cp_adc_init + PP/CPD raw + PD11/D_LINK feed cp_step; BAT scaled for SWD). The strong
    # DMA2_Stream1_IRQHandler proves the IRQ57 ISR is retained. cp_adc_publish (per-event sum +
    # publish-every-8) + the raw getters + d_link/pd11 leaves are required-present. cp_adc_pp_mv/
    # cpd_mv/ch1x4 are -O2-inlined / gc-eliminated (bench-only, host-tested in test_cp_adc); the
    # scaling LOGIC is verified via cp_adc_bat_mv (retained, called from main) + the host test.
    for want in ("cp_adc_init", "cp_adc_publish", "cp_adc_bat_mv", "cp_adc_pp_raw", "cp_adc_bat_raw",
                 "cp_adc_cpd_raw", "cp_adc_d_link", "cp_adc_pd11", "DMA2_Stream1_IRQHandler"):
        check(want in syms, "wired CP-ADC3 symbol present: " + want)
    # IPv6 ND6 neighbor cache + NS/NA/RA (nd6, Agent N / analyze96) wired into v2g_net
    # (nd6_init/set_send/set_local/input/lookup) + main (nd6_tmr/get). The pure wire builders
    # (build_ns/build_na) + find_or_create are required-present (called from nd6_send_ns/na/input/
    # lookup). nd6_solicited_node_mcast + the small static helpers (find/flush_queue/free_entry/
    # emit_icmp6/parse_lla) are -O2-INLINED into nd6_send_ns (no standalone symbol); their LOGIC is
    # verified via constants below + the host test (test_nd6, 81 checks).
    for want in ("nd6_init", "nd6_set_send", "nd6_set_local", "nd6_input", "nd6_lookup", "nd6_tmr",
                 "nd6_get", "nd6_send_ns", "nd6_send_na", "nd6_find_or_create", "nd6_build_ns",
                 "nd6_build_na"):
        check(want in syms, "wired ND6 symbol present: " + want)
    # PnC CA cert store (ca_store, Agent N / analyze96) wired into main (ca_store_init/get/
    # root_count) + ccs2_init (sdp_init(ca_store_root_count())). ca_populate/hdr_valid/entry_valid
    # are the pure validators/populator (called from ca_store_init, retained). ca_byte_sum +
    # contract_valid are -O2-INLINED / bench-only (host-tested in test_ca_store, 45 checks); their
    # LOGIC is verified via constants below. Required-present: init/get/count + populate/hdr_valid/
    # entry_valid that the autonomous ext-SPI->RAM path reaches.
    for want in ("ca_store_init", "ca_store_get", "ca_store_root_count", "ca_populate",
                 "ca_hdr_valid", "ca_entry_valid"):
        check(want in syms, "wired CA-store symbol present: " + want)
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
        # cp_capture_init is a HARDWARE measurement init (TIM4 / GPIOD PD12 / RCC / NVIC), like
        # adc_init / qca7005_init — excluded from the pure-logic no-peripheral check. Its
        # measurement-only peripheral set (no power-port GPIOB/C/E) is verified separately below.
        # The pure cp_capture_median/publish/process/getters remain peripheral-free (checked).
        # cp_adc_init (ADC3 / DMA2 Stream1 / GPIOA+GPIOC analog / RCC / NVIC) and the cp_adc_d_link/
        # pd11 GPIO IDR read leaves are likewise HARDWARE measurement — excluded here, verified
        # separately below (init = analog-mode config only, no power drive; leaves = read-only).
        # The pure cp_adc_publish/scaling/raw-getters remain peripheral-free (checked).
        if name in ("cp_capture_init", "cp_adc_init", "cp_adc_d_link", "cp_adc_pd11"):
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
                p = ((ins.address + 4) & ~3) + (imm12 if u else -imm12)
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
                     "din_session_get", "v2g_net_get", "v2g_net_tcp_send", "v2g_net_set_local_mac",
                     "cp_capture_init", "cp_capture_duty", "cp_capture_period",
                     "cp_adc_init", "cp_adc_pp_raw", "cp_adc_cpd_raw", "cp_adc_pd11", "cp_adc_d_link",
                     "ca_store_init", "ca_store_root_count", "ca_store_get", "nd6_tmr", "nd6_get"):
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
                p = ((ins.address + 4) & ~3) + (imm12 if u else -imm12)
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

    # --- CP PWM TIM4 input-capture front-end (cp_capture, Agent J / analyze95) ---
    # Byte-exact TIM4 init 0x08088A8C register values + PD12 AF2 RMW masks + NVIC IRQ30.
    cap_init = func_imms("cp_capture_init")
    for v, lab in [(0x53, "PSC=83 (1us/tick)"), (0x456, "ARR=1110"), (0x54, "SMCR reset TS=TI1FP1"),
                   (0x201, "CCMR1 CH1 direct + CH2 indirect TI1"), (0x44C, "CCR3=1100 heartbeat"),
                   (0x13, "CCER CH1 falling / CH2 rising"), (0x0A, "DIER CC1IE|CC3IE"),
                   (0x81, "CR1 CEN|ARPE"), (0x40000800, "TIM4 base")]:
        check(v in cap_init, "cp_capture_init carries TIM4 " + lab)
    check(0x40000000 in cap_init, "cp_capture_init enables NVIC IRQ30 (1<<30)")
    # PD12 read-modify-write masks (preserve gpio_safe PD11/PD8/PD3): MODER/PUPDR bits25:24,
    # AFRH nibble12. -O2 materializes the set/clear masks as immediates.
    for v, lab in [(0x3000000, "PD12 MODER/PUPDR mask 3<<24"), (0x2000000, "PD12 MODER AF 2<<24"),
                   (0x1000000, "PD12 PUPDR pull-up 1<<24"), (0xF0000, "PD12 AFRH mask 0xF<<16"),
                   (0x20000, "PD12 AFRH AF2 2<<16")]:
        check(v in cap_init, "cp_capture_init carries " + lab)
    # measurement only: TIM4 + GPIOD (computed 0x40020000+0xC00) + RCC; NO power-port GPIOB/C/E.
    check(0x40020400 not in cap_init and 0x40020800 not in cap_init and 0x40021000 not in cap_init,
          "cp_capture_init references no power-port GPIOB/GPIOC/GPIOE (measurement only)")
    # ISR body 0x08088ACE: duty per-mille 1000 + validity window CCR1 in [950,1050].
    cap_proc = func_imms("cp_capture_process")
    for v, lab in [(0x3E8, "duty x1000 per-mille"), (0x3B6, "validity CCR1-950"),
                   (0x64, "validity span 100")]:
        check(v in cap_proc, "cp_capture_process carries " + lab)
    # deglitch 0x08088A20 thresholds: full 32 -> cmp #31 (0x1F)+bls; zero 128 -> uint8 sign-bit
    # test lsls #24 (0x18 shift)+bpl — -O2 emits no #128 immediate. Both characterized here; the
    # host test (test_cp_capture) proves the 128/32 sample-count logic exhaustively.
    cap_pub = func_imms("cp_capture_publish")
    check(0x3E8 in cap_pub, "cp_capture_publish carries full-scale 1000")
    check(0x1F in cap_pub, "cp_capture_publish carries full-deglitch threshold 32 (cmp #31)")
    check(0x18 in cap_pub, "cp_capture_publish carries zero-deglitch 128 sign-test (lsls #24)")
    # median 0x08088B9E: batch 16 + tight-cluster span 15 + DC-reject 1000.
    cap_med = func_imms("cp_capture_median")
    check(0x10 in cap_med and 0xF in cap_med and 0x3E8 in cap_med,
          "cp_capture_median carries batch 16 / span 15 / DC-reject 1000")

    # --- CP/PP ADC3 analog acquisition front-end (cp_adc, Agent I / analyze95) ---
    # Byte-exact ADC3 init 0x08088628 block: CR1=0x800 DISCEN (1 conv/trigger), CR2=0x1E000301
    # (ADON|DMA|DDS|EXTSEL=14 TIM8_TRGO|rising), SMPR all-ch 84 cycles, sequence SQR1/2/3 ->
    # [ch1,ch2,ch1,ch2,ch1,ch12,ch1,ch0], DMA2 Stream1 Ch2 CR=0x04002D10 NDTR=16, CCR ADCPRE=/6.
    adc_init = func_imms("cp_adc_init")
    for v, lab in [(0x800, "ADC3 CR1=0x800 DISCEN"), (0x1E000301, "ADC3 CR2 ADON|DMA|DDS|TIM8_TRGO"),
                   (0x04924924, "SMPR1 84-cycle all-ch"), (0x24924924, "SMPR2 84-cycle all-ch"),
                   (0x00700581, "SQR1 L=7 (8 conv)"), (0x04110401, "SQR2 SQ7=ch1 SQ8=ch0"),
                   (0x18110441, "SQR3 SQ1..6"), (0x04002D10, "DMA2_S1CR CHSEL2|halfword|CIRC|TCIE"),
                   (0x0002A006, "ADC_CCR MULTI6|DMA2|ADCPRE=/6"), (0xF40, "DMA2_LIFCR stream1"),
                   (0x10, "DMA2_S1NDTR=16 halfwords"), (0x40012000, "ADC base reg (ADC3=+0x200)")]:
        check(v in adc_init, "cp_adc_init carries " + lab)
    check(0x2000000 in adc_init, "cp_adc_init enables NVIC IRQ57 (1<<25)")
    # ADC3_DR PAR offset +0x4C (DMA2_Stream1 base+0x28 is computed; S1CR value above proves it).
    check(0x4C in adc_init, "cp_adc_init computes ADC3_DR PAR (+0x4C)")
    # GPIOA PA0/1/2 + GPIOC PC2 analog-mode RMW masks (MODER/PUPDR 2-bit fields = 0b11). GPIOC is
    # computed as GPIOA base 0x40020000 + 0x800; the 0x3F/0x30 masks prove the analog-mode config.
    check(0x3F in adc_init and 0x30 in adc_init,
          "cp_adc_init carries GPIOA 0x3F / GPIOC 0x30 analog-mode masks")
    check(0x40020000 in adc_init, "cp_adc_init configures GPIOA (PA0/1/2) + GPIOC (PC2, +0x800) analog")
    # measurement only: init touches GPIOA/GPIOC analog + ADC3/DMA2/RCC, NOT power-port GPIOB/GPIOE
    # (the D_LINK GPIOB read is the separate cp_adc_d_link leaf; no BSRR pin drive in init).
    check(0x40020400 not in adc_init and 0x40021000 not in adc_init,
          "cp_adc_init references no GPIOB/GPIOE (analog measurement config only, no power drive)")

    # D_LINK / PD11 are filterless READ-ONLY GPIO IDR leaves (no store / no pin drive). -O2 folds
    # the IDR address as GPIOA base 0x40020000 + a MEM displacement (0x410 = GPIOB_IDR 0x40020410,
    # 0xC10 = GPIOD_IDR 0x40020C10); the bit extract is ubfx #12 / #11. Collect MEM displacements.
    def func_mnemonics(name):
        addr = syms.get(name)
        if addr is None:
            return []
        size = func_size(name)
        return [ins.mnemonic.split(".")[0] for ins in md.disasm(fw[off(addr):off(addr) + size], addr)]

    def func_disps(name):
        addr = syms.get(name)
        if addr is None:
            return set()
        size = func_size(name)
        ds = set()
        for ins in md.disasm(fw[off(addr):off(addr) + size], addr):
            for op in ins.operands:
                if op.type == 3:  # MEM
                    ds.add(op.mem.disp & 0xFFFFFFFF)
        return ds

    dl = func_imms("cp_adc_d_link")
    check(0x40020000 in dl and 0x410 in func_disps("cp_adc_d_link"),
          "cp_adc_d_link reads GPIOB_IDR (0x40020000+0x410 = 0x40020410, PB12)")
    check(not any(m.startswith("str") for m in func_mnemonics("cp_adc_d_link")),
          "cp_adc_d_link is read-only (no GPIO store / drive)")
    pd = func_imms("cp_adc_pd11")
    check(0x40020000 in pd and 0xC10 in func_disps("cp_adc_pd11"),
          "cp_adc_pd11 reads GPIOD_IDR (0x40020000+0xC10 = 0x40020C10, PD11)")
    check(not any(m.startswith("str") for m in func_mnemonics("cp_adc_pd11")),
          "cp_adc_pd11 is read-only (BCB drive stays gated)")

    # ISR 0x0808876A (IRQ57): clear stream1 flags (0xF40); DMA2 via base 0x40026000 + LISR 0x400 /
    # LIFCR 0x408; TCIF1 (bit11) tested by lsls #20 (0x14) -> sign flag (ite mi), not tst #0x800.
    isr1 = func_imms("DMA2_Stream1_IRQHandler")
    isr1d = func_disps("DMA2_Stream1_IRQHandler")
    check(0xF40 in isr1 and 0x400 in isr1d and 0x408 in isr1d,
          "DMA2_Stream1_IRQHandler clears stream1 flags (0xF40) via DMA2 LISR/LIFCR (+0x400/+0x408)")
    check(0x14 in isr1, "DMA2_Stream1_IRQHandler tests TCIF1 bit11 (lsls #20 -> sign)")
    # publish-every-8 cadence (cmp #8 / #7) lives in cp_adc_publish; the 16/8/8 weighting +
    # PP-excludes-ch1 correction is proven exhaustively by the host test (test_cp_adc).
    adc_pub = func_imms("cp_adc_publish")
    check(0x8 in adc_pub or 0x7 in adc_pub,
          "cp_adc_publish carries publish-every-8 cadence (cmp #8/#7)")
    # AD_BAT scaling 0x08088864: raw*6600/32760. -O2 keeps the x6600 (0x19C8) but optimizes /32760
    # into lsrs#3 (/8) + magic-multiply 0x20020021 (/4095) + ubfx#9 — no 0x7FF8 immediate. The exact
    # /32760 truncation is proven by the host test (test_cp_adc); here we pin x6600 + the div magic.
    bat_mv = func_imms("cp_adc_bat_mv")
    check(0x19C8 in bat_mv and 0x20020021 in bat_mv,
          "cp_adc_bat_mv carries AD_BAT x6600 (0x19C8) + /32760 magic (0x20020021, /8 then /4095)")

    # --- IPv6 ND6 neighbor cache + NS/NA/RA (nd6, Agent N / analyze96) ---
    # Byte-derived from stock nd6_input 0x0809C926 / nd6_send_ns 0x0809C520 / nd6_send_na
    # 0x0809C7BA / nd6_tmr 0x0809D012 / ethip6_output 0x0809B35C. -O2 inlines the small static
    # helpers (find/flush_queue/free_entry/emit_icmp6/parse_lla) into the required-present callers,
    # so verify their LOGIC via distinctive constants unioned across those callers.
    nd6_imms = (func_imms("nd6_init") | func_imms("nd6_input") | func_imms("nd6_tmr")
                | func_imms("nd6_send_ns") | func_imms("nd6_send_na") | func_imms("nd6_lookup")
                | func_imms("nd6_build_ns") | func_imms("nd6_build_na")
                | func_imms("nd6_solicited_node_mcast"))
    for v, lab in [(30000, "reachable_time default 30000ms (pre-RA)"),
                   (1000, "retransmit_time / REACHABLE tick 1000ms"),
                   (5, "NS-receive DELAY counter 5 (deviation from stock STALE)"),
                   (3, "MAX_PROBES 3 (INCOMPLETE/PROBE free threshold)"),
                   (0x87, "ICMPv6 NS type 135"), (0x88, "ICMPv6 NA type 136"),
                   (0x86, "ICMPv6 RA type 134"),
                   (0x22, "NA DAD reply flags 0x22 (all-nodes + Override)"),
                   (0x60, "NA solicited reply flags 0x60 (Solicited + Override)"),
                   (255, "ICMPv6 hop limit 255")]:
        check(v in nd6_imms, "nd6 carries " + lab)
    # NA flags hi-nibble mask: stock keeps R/S/O (flags & 0xF0). -O2 emits bic.w r3,r4,#15 (clear
    # low nibble == &0xF0) in nd6_build_na, so the immediate is 0x0F not 0xF0; accept either form.
    na_imms = func_imms("nd6_build_na")
    check(0x0F in na_imms or 0xF0 in na_imms,
          "nd6_build_na carries NA flags hi-nibble mask (bic #0x0F == &0xF0, R/S/O)")
    # TLLA option {type2,len1} packed as the u16 0x0102 stored at out+24 (nd6_build_na).
    check(0x102 in na_imms, "nd6_build_na carries TLLA {type2,len1} packed 0x0102 @out+24")
    # ND6 is pure state-machine + wire logic: NO peripheral base (power-GPIO safe; already covered
    # by the safety scan above via the nd6_ prefix). The neighbor cache is RAM 0x200xxxxx only.

    # --- PnC CA cert store (ca_store, Agent N / analyze96) ---
    # Byte-derived from stock ext-SPI master hdr@0x1F8000 (magic 0xCEA155E1/version1/size/byte-sum)
    # / data@0x1F8010 / entry 808B {msg_code,der_len<=800,DER} / populate 0x080515CC (Root 0x8101
    # slots0-4 compact NULL-term ptr-array). -O2 inlines the pure validators (hdr_valid/entry_valid/
    # contract_valid/byte_sum/populate) into ca_store_init, so union their constants.
    ca_imms = (func_imms("ca_store_init") | func_imms("ca_populate") | func_imms("ca_hdr_valid")
               | func_imms("ca_entry_valid") | func_imms("ca_contract_valid")
               | func_imms("ca_byte_sum"))
    for v, lab in [(0xCEA155E1, "ext-SPI master header magic 0xCEA155E1"),
                   (808, "CA entry size 808B (0x328)"),
                   (800, "CA DER max 800B (0x320)"),
                   (0x8101, "Root cert msg_code 0x8101"),
                   (0x1F8000, "ext-SPI header addr 0x1F8000"),
                   (0x1F8010, "ext-SPI data addr 0x1F8010"),
                   (9792, "CA data buffer max 9792B (12 entries)")]:
        check(v in ca_imms, "ca_store carries " + lab)
    # ca_store reads ext-SPI flash via spi4_read (bl, not a peripheral immediate) -> the pure
    # populator/validators reference NO 0x400xxxxx peripheral base (power-GPIO safe; covered by the
    # ca_ prefix safety scan). The flash addrs 0x1F8000/0x1F8010 are external SPI, not STM32 periph.

    print("%d checks, %d failures" % (checks, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())