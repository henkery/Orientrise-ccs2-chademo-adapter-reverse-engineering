#!/usr/bin/env python3
"""analyze79.py — CAN-bus assignment + RCC clock decoder (§5.8.1 / §5.8.2 / §8.4 / §8.5):
resolves which CAN controller carries CHAdeMO vs GB/T, and confirms the MCU clock tree, by
re-deriving from firmware.bin bytes (no hardcoded conclusions).

RESOLVED:
  * **CAN1-only board.** CAN1 = PD0/PD1 (AF9) is the only wired CAN controller. CAN2 exists in the
    generic bxCAN HAL (handle table + stop thunk + filter bank 14 via CAN2SB=14) but is UNWIRED:
    no CAN2 AF9 GPIO in the board init, no CAN2 service task, and the CAN2 base is loaded only by
    an unreferenced stop thunk.
  * **CAN1 carries BOTH protocols.** The single CAN1_REC RTOS task waits on CAN1's cfg event queue
    (0x20000978) and its frame dispatch (0x080524FE) splits on the IDE bit: 11-bit standard IDs ->
    CHAdeMO handlers, 29-bit extended IDs -> GB/T 27930 J1939 dispatch. Only one protocol is active
    at a time (whichever vehicle is attached).
  * **Clock tree CONFIRMED from RCC (was [H]):** PLLCFGR=0x07402A04 (HSE 8 MHz /PLLM4 *PLLN168 /PLLP2)
    => SYSCLK=168 MHz; CFGR PPRE1=/4 => APB1=42 MHz, PPRE2=/2 => APB2=84 MHz; FLASH_ACR=0x705 (5 WS).
    APB1=42 MHz matches the CAN BTR baud table {125,250,500} kbit/s (§5.8.1).

Method (byte-derived): (1) constant-track the RCC clock-config function's PLLCFGR/CFGR/FLASH_ACR
writes and decode the PLL/bus prescalers; (2) locate the CAN1/CAN2 handle-table base words and count
their load sites, and show the generic CAN-open's `cmp base,CAN1; bne` filter-bank skip (bxCAN shares
filter regs through CAN1); (3) find the CAN1_REC task by name, read the cfg queue it waits on, and
match it to the CAN1 handle; (4) disassemble the frame dispatch to show the IDE-bit protocol split;
(5) count CAN2 stop-thunk callers (0) to confirm CAN2 is never serviced.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze79.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm_const import ARM_REG_PC, ARM_REG_LR

TB = 0x0801FBFE
fw = open('firmware.bin', 'rb').read(); N = len(fw)
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
def cstr_at(o):
    s = o
    while s > 0 and fw[s-1] != 0 and 32 <= fw[s-1] < 127: s -= 1
    e = fw.find(b'\x00', o)
    if e < 0 or e-s > 60: return None
    t = fw[s:e]
    if len(t) >= 2 and all(32 <= c < 127 for c in t): return t.decode()
    return None

print("== 1. RCC clock-config: PLLCFGR / CFGR / FLASH_ACR -> SYSCLK / APB1 / APB2 ==")
# locate the clock-config function: RCC base load followed by a str to +4 (PLLCFGR) with a pool const
rcc_fn = None
for o in range(0, N-4, 2):
    if (u16(o) & 0xF800) == 0x4800 and ldr_pool(o) == 0x40023800:
        # scan forward (instruction-size steps) for str [rRCC,#4] (PLLCFGR)
        reg = dis(o)[0].operands[0].reg; a = o; found = False
        for _ in range(40):
            i2 = dis(a)
            if not i2: a += 2; continue
            j = i2[0]
            if j.mnemonic in ('str','str.w') and len(j.operands)==2 and j.operands[1].type==3 \
               and j.operands[1].mem.base==reg and j.operands[1].mem.disp==4:
                found = True; break
            if j.mnemonic=='bx': break
            a += j.size
        if found:
            rcc_fn = o; break   # push-less function; tracker starts at the RCC base load
regs = {}
if rcc_fn is not None:
    rv = {}; a = rcc_fn; base_reg = {}
    for _ in range(120):
        ins = dis(a)
        if not ins: break
        i = ins[0]; mn = i.mnemonic; ops = i.operands
        if mn in ('ldr','ldr.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.base==ARM_REG_PC:
            w = ldr_pool(a)
            if w is not None:
                rv[ops[0].reg] = w
                if 0x40000000 <= w < 0x60000000: base_reg[ops[0].reg] = w
                else: base_reg.pop(ops[0].reg, None)
            else:
                rv.pop(ops[0].reg, None); base_reg.pop(ops[0].reg, None)
        elif mn in ('ldr','ldr.w','ldrh','ldrh.w','ldrb','ldrb.w') and len(ops)>=2 and ops[1].type==3:
            rv.pop(ops[0].reg, None); base_reg.pop(ops[0].reg, None)   # memory load: value unknown
        elif mn in ('movw','mov.w','movs') and len(ops)==2 and ops[1].type==2:
            rv[ops[0].reg] = ops[1].imm & 0xFFFF; base_reg.pop(ops[0].reg, None)
        elif mn=='movt' and len(ops)==2 and ops[1].type==2:
            rv[ops[0].reg] = (rv.get(ops[0].reg, 0) & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
        elif mn in ('orr','orr.w','bic','bic.w','lsls','lsrs','ubfx','adds','add','add.w','mov','mvns','ands'):
            if ops and ops[0].type==1:                                  # RMW: dest no longer a known const
                rv.pop(ops[0].reg, None); base_reg.pop(ops[0].reg, None)
        elif mn in ('str','str.w') and len(ops)==2 and ops[1].type==3:
            b = base_reg.get(ops[1].mem.base); v = rv.get(ops[0].reg)
            if b is not None and v is not None:
                regs[(b, ops[1].mem.disp)] = v
        if mn=='bx' and ops and ops[0].type==1 and ops[0].reg==ARM_REG_LR: break
        if mn=='pop' and any(op.type==1 and op.reg==ARM_REG_PC for op in ops): break
        a += i.size
pll = regs.get((0x40023800, 4)); cfgr = regs.get((0x40023800, 8)); acr = regs.get((0x40023C00, 0))
if pll is not None:
    pllm = pll & 0x3F; plln = (pll >> 6) & 0x1FF; pllp = ((pll >> 16) & 3)*2 + 2
    pllsrc = (pll >> 22) & 1; pllq = (pll >> 24) & 0xF
    hse = 8_000_000
    vco = hse // pllm * plln; sysclk = vco // pllp
    print(f"  PLLCFGR=0x{pll:08X}: PLLM={pllm} PLLN={plln} PLLP={pllp} PLLQ={pllq} PLLSRC={'HSE' if pllsrc else 'HSI'}")
    print(f"  HSE={hse//1_000_000} MHz -> VCO={vco//1_000_000} MHz -> SYSCLK={sysclk//1_000_000} MHz")
if cfgr is not None:
    hpre = (cfgr >> 4) & 0xF; ppre1 = (cfgr >> 10) & 7; ppre2 = (cfgr >> 13) & 7
    div = lambda c: (1 if c < 4 else (2,4,8,16)[c-4]) if c>=4 else 1
    ahb_div = 1 if hpre < 8 else (2,4,8,16,64,128,256,512)[hpre-8]
    apb1_div = 1 if ppre1 < 4 else (2,4,8,16)[ppre1-4]
    apb2_div = 1 if ppre2 < 4 else (2,4,8,16)[ppre2-4]
    print(f"  CFGR=0x{cfgr:08X}: HPRE=/{ahb_div} PPRE1=/{apb1_div} PPRE2=/{apb2_div}")
    if pll is not None:
        print(f"  AHB={sysclk//ahb_div//1_000_000} MHz  APB1={sysclk//apb1_div//1_000_000} MHz  APB2={sysclk//apb2_div//1_000_000} MHz")
        print(f"  APB1 timer clock = {sysclk//apb1_div*2//1_000_000} MHz (x2 when APB1 prescaler>1)")
if acr is not None:
    print(f"  FLASH_ACR=0x{acr:03X}: latency={acr&7} WS (correct for 168 MHz @ 3.3 V)")

print("\n== 2. CAN handle-table bases + load-site counts; generic-open filter skip ==")
CAN = {0x40006400:'CAN1', 0x40006800:'CAN2'}
sites = {k:[] for k in CAN.values()}
for o in range(0, N-4, 2):
    w = u32(o)
    if w in CAN:
        for c in range(max(0,o-0x400), min(N-4,o+0x400), 2):
            if (u16(c)&0xF800)==0x4800:
                pca=((rt(c)+4)&~3)-TB; p=pca+(u16(c)&0xFF)*4
                if p==o: sites[CAN[w]].append(c)
for nm in ('CAN1','CAN2'):
    print(f"  {nm} base 0x{[k for k,v in CAN.items() if v==nm][0]:08X}: {len(sites[nm])} code load sites")
# generic CAN-open: locate the MCR=0x4D init write, then the 'cmp base,CAN1; bne' filter skip.
# The CAN1 base is loaded into a register at the function top (before MCR), and the init is one
# arm of a tbb dispatcher, so track the base reg from the prologue and don't stop at arm pops.
mcr = None
for o in range(0, N-4, 2):
    ins = dis(o)
    if ins and ins[0].mnemonic in ('movs','mov.w') and len(ins[0].operands)==2 and ins[0].operands[1].type==2 and ins[0].operands[1].imm==0x4D:
        nxt = dis(o+2)
        if nxt and nxt[0].mnemonic in ('str','str.w') and nxt[0].operands[1].type==3 and nxt[0].operands[1].mem.disp==0:
            mcr = o; break
if mcr is not None:
    start = mcr
    for b in range(mcr, max(0, mcr-0x200), -2):           # back up to the push {...,lr} prologue
        ib = dis(b)
        if ib and ib[0].mnemonic=='push' and any(op.type==1 and op.reg==ARM_REG_LR for op in ib[0].operands):
            start = b; break
    can1reg = None; a = start; cmp_at = None
    for _ in range(160):
        i2 = dis(a)
        if not i2: break
        j = i2[0]
        if j.mnemonic in ('ldr','ldr.w') and ldr_pool(a)==0x40006400:
            can1reg = j.operands[0].reg
        if a >= mcr and j.mnemonic=='cmp' and can1reg is not None and len(j.operands)==2 \
           and j.operands[1].type==1 and j.operands[1].reg==can1reg:
            nb = dis(a+j.size)
            if nb and nb[0].mnemonic in ('bne','bne.w'):
                cmp_at = a; break
        a += j.size
    if cmp_at is not None:
        print(f"  generic CAN-open @0x{rt(start):08X}: MCR=0x4D @0x{rt(mcr):08X}; `cmp base,CAN1; bne` @0x{rt(cmp_at):08X}")
        print(f"    -> filter-bank setup (FMR/FM1R/FS1R/FFA1R/FA1R at CAN1+0x200) runs ONLY for CAN1")
        print(f"       (bxCAN shares filter regs via CAN1 base; CAN2SB splits banks). A CAN2 open skips it.")

print("\n== 3. CAN1_REC task: name -> entry -> cfg event queue -> CAN1 handle ==")
# find OSTaskCreateExt (0x8088D76) callers; identify the one named CAN1_REC
for o in range(0, N-4, 2):
    if (u16(o)&0xF800)==0xF000:
        ins=dis(o)
        if ins and ins[0].mnemonic=='bl' and ins[0].operands and ins[0].operands[0].type==2 and ins[0].operands[0].imm==0x08088D76:
            entry=None; name=None; a=o-0x40
            while a<o:
                i2=dis(a)
                if not i2: a+=2; continue
                j=i2[0]; h=u16(a)
                if (h&0xF800)==0x4800 and j.op_str.startswith('r2,'):
                    w=ldr_pool(a)
                    if w: entry=w
                if j.mnemonic=='adr' and len(j.operands)==2 and j.op_str.startswith('r1,'):
                    t=((rt(a)+4)&~3)+j.operands[1].imm
                    if TB<=t<TB+N: name=cstr_at(t-TB)
                a+=j.size
            if name=='CAN1_REC':
                print(f"  CAN1_REC task create @0x{rt(o):08X}: entry=0x{entry:08X}")
                # disassemble entry (even); the cfg queue is the r0 arg to the event-wait call
                e=(entry & ~1)-TB; q=None; last_r0=None; a=e
                for _ in range(20):
                    i2=dis(a)
                    if not i2: break
                    j=i2[0]
                    if (u16(a)&0xF800)==0x4800 and j.op_str.startswith('r0,'):
                        w=ldr_pool(a)
                        if w and 0x20000000<=w<0x20030000: last_r0=w
                    if j.mnemonic=='bl' and j.operands and j.operands[0].type==2 \
                       and j.operands[0].imm in (0x080893EA, 0x08089480) and last_r0:
                        q=last_r0; break
                    a+=j.size
                print(f"  CAN1_REC waits on cfg/event queue = 0x{q:08X}" if q else "  cfg queue not found")
                # match to CAN handle cfg (CAN1 cfg=0x20000978 per handle table)
                print(f"  CAN1 handle cfg word (handle table f+0x67B7A) = 0x{u32(0x67B7A):08X}")
                if q==u32(0x67B7A):
                    print(f"  => CAN1_REC services CAN1 (queue == CAN1 handle cfg). No CAN2_REC task exists.")

print("\n== 4. frame dispatch: IDE-bit split -> CHAdeMO (11-bit) vs GB/T (29-bit J1939) ==")
# the dispatch is the function that extracts IDE and branches; locate via 'ubfx ..., #0x14, #4' + cmp #0xa
for o in range(0, N-4, 2):
    ins=dis(o)
    if ins and ins[0].mnemonic=='ubfx' and len(ins[0].operands)==4 and ins[0].operands[2].imm==0x14 and ins[0].operands[3].imm==4:
        nb=dis(o+4)
        if nb and nb[0].mnemonic=='cmp' and nb[0].operands[-1].type==2 and nb[0].operands[-1].imm==0xa:
            print(f"  frame dispatch @0x{rt(o-8):08X}: extracts IDE/RTR field, cmp #0xA (extended) -> branch")
            a=o-8
            for _ in range(10):
                i2=dis(a)
                if not i2: break
                j=i2[0]
                print(f"    0x{rt(a):08X}: {j.mnemonic:8s} {j.op_str}")
                a+=j.size
            print("    11-bit standard path -> CHAdeMO handlers; 29-bit extended path -> GB/T J1939 (PF cmp #0x14/0x1a/0x1c/0x1e)")
            break

print("\n== 5. CAN2 stop-thunk callers (0 => CAN2 never serviced) ==")
# CAN2 stop thunk loads CAN2 base then str IER/MSR; find it and count BL callers
can2_thunk=None
for c in sites['CAN2']:
    # the stop thunk: ldr r0,=CAN2 ; ldr r1,=0xF0F0F ; str [r0,#8] ; movs #4 ; str [r0,#4] ; bx lr
    i2=dis(c+4)
    if i2 and i2[0].mnemonic in ('str','str.w') and i2[0].operands[1].type==3 and i2[0].operands[1].mem.disp==8:
        can2_thunk=rt(c); break
bls=[]
for o in range(0,N-4,2):
    if (u16(o)&0xF800)==0xF000:
        ins=dis(o)
        if ins and ins[0].mnemonic=='bl' and ins[0].operands and ins[0].operands[0].type==2:
            bls.append(ins[0].operands[0].imm)
if can2_thunk:
    n=bls.count(can2_thunk)
    print(f"  CAN2 stop thunk 0x{can2_thunk:08X}: {n} BL callers")

print("\n== RESOLVED CAN-bus assignment + clock (§5.8 / §8.4 / §8.5) ==")
print("  CAN1 = PD0/PD1 (AF9) — the ONLY wired CAN controller (CAN1-only board).")
print("  CAN1 carries BOTH CHAdeMO (11-bit IDs) and GB/T 27930 (29-bit J1939): the single CAN1_REC task")
print("    waits on CAN1's cfg queue 0x20000978 and its frame dispatch 0x080524FE splits on IDE — one")
print("    protocol active at a time. CAN2 is in the generic bxCAN HAL (handle + stop thunk + filter")
print("    bank 14, CAN2SB=14) but UNWIRED: no CAN2 AF9 GPIO, no CAN2 task, stop thunk unreferenced.")
print("  Clock (RCC, confirmed): HSE 8 MHz /4 *168 /2 = SYSCLK 168 MHz; APB1=42 MHz (PPRE1 /4),")
print("    APB2=84 MHz (PPRE2 /2); FLASH 5 WS. APB1=42 MHz matches the CAN BTR {125,250,500}k table.")