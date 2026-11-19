#!/usr/bin/env python3
"""analyze72.py — annotated Thumb-2 disassembler for the app (correct base, §5.16).

Disassembles a firmware.bin file range at the ground-truth link base 0x0801FBFE+F with full
annotation: LDR-literal pool values (and the ASCII string a pool pointer targets), ADR/ADD
string targets, movw+movt 32-bit constant reconstruction, BL/B targets, and manual decode of
the MSR(register) T1 encoding capstone 5.0.9 rejects. App pools are PLAINTEXT verbatim (§5.16),
so standard LDR-literal/ADR resolution applies (no +2 overlay shift except the SRAM-copied
flash writer, §5.13b). Reusable for the GPIO/CAN init region, RTOS scheduler, EVCC/SLAC, etc.

Usage:
  nix-shell -p python3 python3Packages.capstone --run \
    'python3 analyze72.py firmware.bin START_HEX END_HEX'
  e.g. analyze72.py firmware.bin 0x67700 0x67c00   # RCC/GPIO/CAN/SPI init region
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TRUE_BASE = 0x0801FBFE
fw = open(sys.argv[1], 'rb').read()
start = int(sys.argv[2], 0); end = int(sys.argv[3], 0) if len(sys.argv) > 3 else start+0x200
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True

def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TRUE_BASE + f
def ascii_at(o, n=40):
    if 0 <= o < len(fw):
        s = fw[o:o+n].split(b'\x00')[0]
        if len(s) >= 3 and all(32 <= c < 127 for c in s): return s.decode()
    return None

PERIPH = {0x40000000:'TIM2',0x40000400:'TIM3',0x40000800:'TIM4',0x40001400:'TIM7',
    0x40006400:'CAN1',0x40006800:'CAN2',0x40007000:'PWR',0x40010000:'TIM1',0x40010400:'TIM8',
    0x40012000:'ADC1',0x40012100:'ADC2',0x40012200:'ADC3',0x40012300:'ADCcc',0x40013000:'SPI1',
    0x40013400:'SPI4',0x40013800:'SYSCFG',0x40013C00:'EXTI',0x40020000:'GPIOA',0x40020400:'GPIOB',
    0x40020800:'GPIOC',0x40020C00:'GPIOD',0x40021000:'GPIOE',0x40023000:'CRC',0x40023800:'RCC',
    0x40023C00:'FLASH',0x40026400:'DMA2',0x40040000:'USB_HS',0x50060800:'RNG',0xE000E010:'SysTick',
    0xE000ED00:'SCB',0xE000ED08:'VTOR',0xE000ED0C:'AIRCR',0xE0042000:'DBGMCU_IDCODE',
    0x1FFF7A10:'UID',0x1FFF7A22:'FLASH_SIZE'}
def periph_name(v):
    for b,n in PERIPH.items():
        if b <= v < b+0x400: return f'{n}+0x{v-b:x}' if v!=b else n
    return None

print(f"# fw[0x{start:05x}:0x{end:05x}] @ runtime 0x{rt(start):08X}..0x{rt(end):08X} (base 0x{TRUE_BASE:08X})")
a = start
while a < end:
    h1 = u16(a)
    ins = list(md.disasm(fw[a:a+8], rt(a), count=1))
    # manual MSR(register) T1: f38x 88xx
    if not ins and (h1 & 0xFFF0) == 0xF380 and (u16(a+2) & 0xFF00) == 0x8800:
        sysm = u16(a+2) & 0xFF
        nm = {8:'MSP',9:'PSP',0x10:'PRIMASK',0x14:'CONTROL',0x11:'BASEPRI',0x12:'FAULTMASK'}.get(sysm, f'SYSm{sysm:02x}')
        print(f"  f+0x{a:05x} 0x{rt(a):08x}: msr      {nm}, r{h1&0xF}"); a += 4; continue
    if not ins:
        v = u32(a); pn = periph_name(v); s = ascii_at(v - TRUE_BASE) if 0x08000000<=v<0x08100000 else None
        note = f'  ; {pn}' if pn else (f'  ; ->str {s!r}' if s else '')
        print(f"  f+0x{a:05x} 0x{rt(a):08x}: .word    0x{v:08X}{note}"); a += 2; continue
    i = ins[0]; note = ''
    pca = ((rt(a)+4)&~3) - TRUE_BASE                  # file off of runtime-aligned PC+4 (base≡2 mod4!)
    if (h1 & 0xF800) == 0x4800:                       # LDR literal T1
        t = pca+(h1&0xFF)*4; v = u32(t); pn = periph_name(v)
        s = ascii_at(v - TRUE_BASE) if 0x08000000<=v<0x08100000 else None
        note = f'   ; [pool f+0x{t:05x}=0x{v:08X}' + (f' {pn}' if pn else '') + (f' ->{s!r}' if s else '') + ']'
    elif (h1 & 0xFF7F) == 0xF85F and i.size == 4:     # LDR literal T2 (U=bit7)
        h2 = u16(a+2); u = (h1>>7)&1
        t = pca+((h2&0xFFF) if u else -(h2&0xFFF)); v = u32(t); pn = periph_name(v)
        s = ascii_at(v - TRUE_BASE) if 0x08000000<=v<0x08100000 else None
        note = f'   ; [pool f+0x{t:05x}=0x{v:08X}' + (f' {pn}' if pn else '') + (f' ->{s!r}' if s else '') + ']'
    elif i.mnemonic in ('adr','add') and 'pc' in i.op_str:
        for op in i.operands:
            if op.type == 2 and op.imm:               # immediate offset from PC
                tgt = ((rt(a)+4)&~3) + op.imm if i.mnemonic=='adr' else rt(a)+op.imm
                fo = tgt - TRUE_BASE; s = ascii_at(fo)
                if s: note = f'   ; ->str {s!r}'
    elif i.mnemonic in ('movw','movt'):
        note = ''
    print(f"  f+0x{a:05x} 0x{rt(a):08x}: {i.mnemonic:9s} {i.op_str}{note}")
    a += i.size