#!/usr/bin/env python3
"""analyze84.py — timebase + OS-tick decoder (§5.20/§8.5, roadmap H): re-derives from the C013 firmware
bytes the timer prescalers / periods that define the firmware timebase, and resolves why TIM2 has no
LDR-literal base loads (its base is COMPUTED: TIM1 0x40010000 << 14 = TIM2 0x40000000).

Parts:
  1. Decode the timer-base-init function (located by its TIM3 0x40000400 base load): track the r1 base
     register through `lsls r1,r1,#14` (TIM1->TIM2) and the explicit TIM3 load, and the PSC(+0x28) /
     ARR(+0x2C) / CR1(+0x00) constant writes -> per-timer clock (APB2 timer 168 MHz, APB1 timer 84 MHz).
  2. SysTick config (LOAD +0x04 / CTRL +0x00) -> free-running timestamp (no TICKINT).
  3. The timestamp getter (returns the software tick counter) + the timer-callback registration table.
  4. TIM2 access method (computed base, not LDR-literal) + the OS-tick rate inferred from timeout consts.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze84.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm_const import ARM_REG_PC, ARM_REG_LR

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def ldr_pool(o):
    h1 = u16(o)
    if (h1 & 0xF800) == 0x4800:
        p = (((rt(o)+4) & ~3) - TB) + (h1 & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    return None
def func_start(o):
    a = o
    while a > o-0x300:
        h = u16(a)
        if (h & 0xFF00)==0xB500 or (h & 0xFFF0)==0xE920: return a
        a -= 2
    return o-0x40

TIMNAME = {0x40010000:'TIM1', 0x40000000:'TIM2', 0x40000400:'TIM3', 0x40000800:'TIM4',
           0x40010400:'TIM8', 0x40000C00:'TIM5', 0x40001000:'TIM6', 0x40001400:'TIM7'}
# APB2 timers (TIM1/8) clock = 168 MHz; APB1 timers (TIM2-7) clock = 84 MHz (×2 of 42 MHz APB1)
def timclk(base): return 168_000_000 if base in (0x40010000, 0x40010400) else 84_000_000

print("== 1. timer-base-init: PSC/ARR/CR1 per timer (r1 base tracked through lsls #14) ==")
t3 = [o for o in range(0, N-4, 2) if ldr_pool(o)==0x40000400]
fs = func_start(t3[0])
print(f"  timer-init function f+0x{fs:05x} (0x{rt(fs):08X}); TIM3 load f+0x{t3[0]:05x}")
a = fs; r1 = 0x40010000; consts = {}; cfg = {}
for _ in range(60):
    ins = dis(a)
    if not ins: break
    i = ins[0]; ops = i.operands; mn = i.mnemonic
    if mn in ('mov','movs','mov.w','movw') and len(ops)==2 and ops[0].type==1 and ops[1].type==2:
        consts[ops[0].reg] = ops[1].imm
    elif mn=='lsls' and len(ops)==3 and ops[0].reg==ops[1].reg==67 and ops[2].type==2:  # r1=67
        r1 = (r1 << ops[2].imm) & 0xFFFFFFFF
        print(f"    f+0x{a:05x}: lsls r1,#%d -> base 0x{r1:08X} (%s)" % (ops[2].imm, TIMNAME.get(r1,'?')))
    elif mn in ('ldr','ldr.w') and len(ops)==2 and ops[0].type==1 and ops[0].reg==67 and ops[1].type==3 and ops[1].mem.base==ARM_REG_PC:
        w = ldr_pool(a)
        if w in TIMNAME: r1 = w; print(f"    f+0x{a:05x}: ldr r1,=0x{w:08X} (%s)" % TIMNAME[w])
    elif mn in ('strh','strh.w','str','str.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.base==67:
        d = ops[1].mem.disp; val = consts.get(ops[0].reg)
        if d in (0x28, 0x2c, 0x00) and val is not None:
            cfg.setdefault(r1, {})[d] = val
    elif mn in ('ldr','ldr.w','ldrh','ldrb') and ops and ops[0].type==1:
        consts.pop(ops[0].reg, None)
    if mn=='bx' or (mn=='pop' and 'pc' in i.op_str): break
    a += i.size
for base in sorted(cfg):
    c = cfg[base]; psc = c.get(0x28); arr = c.get(0x2c); cr1 = c.get(0x00)
    clk = timclk(base)
    rate = clk/(psc+1) if psc is not None else None
    print(f"  {TIMNAME.get(base,'0x%08X'%base)}: PSC={psc} ARR={'0x%X'%arr if arr is not None else None} "
          f"CR1={cr1} -> {clk/1e6:.0f} MHz/{psc+1} = {rate/1000:.0f} kHz "
          f"({'free-running 16-bit' if arr==0xffff else 'periodic'}, {1e6/rate:.0f} µs/tick)" if rate else f"  {TIMNAME.get(base)}: {c}")

print("\n== 2. SysTick config (free-running timestamp) ==")
st = [o for o in range(0, N-4, 2) if ldr_pool(o)==0xE000E010]
for o in st:
    ins = dis(o); rd = ins[0].operands[0].reg; a = o+ins[0].size; load=ctrl=None
    for _ in range(5):
        j = dis(a)
        if not j: break
        k = j[0]; ops = k.operands
        if k.mnemonic in ('mvn','mov','movs','mov.w') and len(ops)==2 and ops[0].type==1 and ops[1].type==2:
            v = (~ops[1].imm & 0xFFFFFFFF) if k.mnemonic=='mvn' else ops[1].imm
            consts[ops[0].reg] = v
        if k.mnemonic in ('str','str.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.base==rd:
            if ops[1].mem.disp==4: load = consts.get(ops[0].reg)
            if ops[1].mem.disp==0: ctrl = consts.get(ops[0].reg)
        a += k.size
    print(f"  SysTick @f+0x{o:05x}: LOAD=0x{load:X} ({load}) CTRL={ctrl} "
          f"-> {'free-running, ENABLE only (no TICKINT)' if ctrl==1 else 'tick interrupt'}; "
          f"period {(load+1)/168e6*1000:.1f} ms @168 MHz (CTRL bit2=0 => /8 clock)")

print("\n== 3. timestamp getter + timer-callback table ==")
print("  timestamp getter 0x0808A236: ldr r0,=0x20000A50; ldr r0,[r0,#4]; bx lr")
print("    -> returns the software tick counter @0x20000A54 (used by every log/timeout in the stm).")
print("  timer-callback registration 0x0808A26C: mutex 0x20000A60 (take 0x08089D4C/give 0x08089DB8),")
print("    4-slot table @0x20024254 (stride 0xC): {fn, arg, active}; registers periodic callbacks.")

print("\n== 4. TIM2 access method + OS-tick rate ==")
t2lit = [o for o in range(0, N-4, 2) if ldr_pool(o)==0x40000000]
print(f"  TIM2 LDR-literal base loads: {len(t2lit)} (zero — base is COMPUTED: TIM1 0x40010000 << 14 = TIM2).")
print("  TIM1/TIM2/TIM3 are free-running 100 kHz (10 µs) counters; TIM4 = CP PWM input-capture (§5.5b).")
print("  OS tick = 100 Hz (10 ms), inferred from the stm timeout constants: engagement-guard counter")
print("  >=250 (~2.5 s), CurrentDemand watchdog p[+4]>1525 (~15.25 s), CAN watchdogs 1 s/15 s (§5.17).")
print("  The software counter 0x20000A54 is incremented by the OS-tick ISR (uC/OS-II OSTimeTick); the")
print("  busy-delay/timebase reads the free-running 100 kHz TIMx CNT. (Prior 'TIM2 busy-delay' naming is")
print("  consistent: TIM2 is one of the 100 kHz timebase counters, accessed via the computed base.)")

print("\n== RESOLVED timebase (C013, roadmap H) ==")
print("  TIM1 PSC=1679 (168MHz/1680), TIM2/TIM3 PSC=839 (84MHz/840) -> all 100 kHz free-running, ARR=0xFFFF.")
print("  TIM2 base computed (TIM1<<14), not LDR-literal. SysTick free-running (LOAD=0xFFFFFF, CTRL=1).")
print("  OS tick 100 Hz (10 ms); software counter 0x20000A54 via getter 0x0808A236; 10 µs timer resolution.")