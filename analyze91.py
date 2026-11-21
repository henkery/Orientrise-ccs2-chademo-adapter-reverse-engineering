#!/usr/bin/env python3
"""analyze91.py — QCA7005 PLC SPI1 host driver + MME/Ethernet transport, byte-exact (REPORT §5.9).

Re-derives from the C013 firmware bytes the QCA7005 SPI1 transport that carries the CCS2 EVCC
traffic (SLAC MME + SDP/V2GTP over TCP/IP). CORRECTS the C009-era anchors used in earlier notes:
the high-level driver is at 0x08089xxx (not 0x08088xxx) and the SPI1 primitives at
0x08093C66–0x08093F7A (the "SPI byte driver @0x080934BE" anchor is a bit-field parser, not SPI).

Resolved transport (replicated INERT in custom_fw/src/qca7005.c, host-tested test_qca7005.c):
  SPI1: PA5 SCK/PA6 MISO/PA7 MOSI AF5, CS=PA4 (active-low), reset=PC5, IRQ=PC4 (polled).
        CR1=0x0357 (Mode 3 CPOL=CPHA=1, master, fPCLK2/8, 8-bit, MSB, SSM+SSI, full-duplex), CR2=0.
  reg read  = CS↓ [0xC0|addr_hi, addr_lo] + 2 dummy → u16 BE   (0x08093CBC)
  reg write = CS↓ [0x40|addr_hi, addr_lo, val_hi, val_lo]      (0x08093D00)
  buf-WRITE = pad-to-60, TX-free reg 0x200 ≥ padded+14, reg 0x100=padded+10, then CS↓
              [00,00] + 4×0xAA sync + len(LE) + [00,01] + data + pad + 2×0x55 + CS↑  (0x08093DA8)
  buf-READ  = RX-avail reg 0x300, reg 0x100=n, CS↓ [80,00] + clock out n + CS↑       (0x08093D44)
  reg-init  = read 0x1A00 ×3 (sig 0xAA55), write 0x400=0x80, 0x1B00=0, 0x1200=0xC5B,
              0xC00=0x447, 0xD00=0x41                                            (0x08089422)
  CPU-ready = sig 400×10 ms, reg 0xC00 bit6 1000×10 ms, reg-init, MAC-read ×3       (0x080895A8)
  reset     = PC5 low 2 ms → high 2 ms                                          (0x08089624)
  MAC-read  = MMTYPE 0xA000 REQ / 0xA001 CNF, param 0xB000+'R'+4 zero, 24 B; template
              @0x080AFDCC dest 00:B0:52:00:00:01 src FE:FF:FE:FF:00:01; MAC = CNF src-MAC.
  RX ring   = 4096 B, packet [L:4 BE][0xAAAAAAAB:4][fp=L-10:2][rsv:2], frame@+0xC, sl=L+4.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze91.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f): return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
def pool(o):
    h = u16(o)
    if (h & 0xF800) == 0x4800:
        p = (((rt(o)+4) & ~3) - TB) + (h & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    if (h & 0xFF7F) == 0xF85F and o+4 <= N:
        U = (h >> 7) & 1; imm = u16(o+2) & 0xFFF; b = ((rt(o)+4) & ~3)
        p = (b+imm if U else b-imm) - TB
        if 0 <= p and p+4 <= N: return u32(p)
    return None

def dump(addr, n, label, stop=True):
    """Function-aware dump; stop=False for functions with conditional early-return pops
    (reg-init / buf-write) so the success path past the first pop is still shown."""
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " GPIOA" if w == 0x40020000 else " GPIOC" if w == 0x40020800 else
                   " SPI1" if w == 0x40013000 else "")
            ex = f"  ; =0x{w:08X}{tag}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:9s} {i.op_str}{ex}")
        a += i.size
        if stop and i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if stop and i.mnemonic == 'pop' and 'pc' in i.op_str: break

print("################ QCA7005 SPI1 TRANSPORT (§5.9, byte-exact, C013) ################")
dump(0x08093CA0, 14, "SPI1 CR1 init (0x317 config -> 0x357 enable, Mode 3 /8 master 8-bit MSB SSM)")
dump(0x08093CBC, 22, "SPI reg-READ (cmd 0xC000|addr, 2 bytes + 2 dummy -> u16 BE)")
dump(0x08093D00, 22, "SPI reg-WRITE / buffer header (cmd 0x4000|addr + u16 BE)")
dump(0x08089422, 50, "QCA7005 reg-init (sig 0xAA55 + 5 config writes)", stop=False)
print("  reg-init: read 0x1A00 ×3 == 0xAA55; write 0x400=0x80, 0x1B00=0, 0x1200=0xC5B,")
print("            0xC00=0x447, 0xD00=0x41. (success path past the bad-sig early-return pop)")
dump(0x08093DA8, 60, "SPI buf-WRITE head (pad-to-60, TX-free 0x200, reg 0x100=padded+10)", stop=False)
dump(0x08093DFC, 60, "SPI buf-WRITE framing (4×0xAA sync, len LE, [00,01], data, pad, 2×0x55)", stop=False)
dump(0x0808955C, 42, "MAC-read REQ builder (MMTYPE 0xA000, EtherType 0xE188, param 0xB000+'R', 24 B)")
dump(0x08089624, 22, "QCA7005 reset pulse (PC5 BSRR 0x200000 low 2 ms -> 0x20 high 2 ms)")

t = 0x080AFDCC - TB
print(f"\n== 12-byte MAC header template @0x080AFDCC ==")
print(f"  {fw[t:t+12].hex(' ')}")
print("  dest = 00:B0:52:00:00:01 (PIB MAC)   src = FE:FF:FE:FF:00:01 (host)")

print("\n== RESOLVED QCA7005 transport API (C013) ==")
print("  SPI1 primitives 0x08093C66–0x08093F7A; high-level driver 0x08089010–0x08089708.")
print("  reg map: 0x100 buf-cmd, 0x200 TX-free, 0x300 RX-avail, 0x400 SPI-rst(0x80),")
print("           0xC00 int/status(0x447; bit0 RX-avail, bit6 CPU-ready), 0xD00 int-timeout(0x41),")
print("           0x1200 SPI-cfg(0xC5B), 0x1A00 CPU-ready sig(0xAA55), 0x1B00 sig-clear(0).")
print("  frame: destMAC[6]+srcMAC[6]+EtherType(88E1)+MMV[1]+MMTYPE[2 LE]+payload; MME built in code.")
print("  RX ring 4096 B @0x20022961; MAC resp buf @0x20022838, PIB MAC @0x2002283E (accessor 0x080896C0).")
print("  generic send 0x080892E2 (mutex->buf-WRITE->mutex->log); RX dispatch 0x0808938A (callback per frame);")
print("  RX task 0x08089486 polls PC4 + reg 0xC00. Replicated INERT in custom_fw/src/qca7005.c")
print("  (bare-metal: no RTOS mutex, tick_delay_ms IWDG-fed, RX polled from qca7005_service).")
print("  Communication transport only — drives NO power-stage GPIO. Host-tested test_qca7005.c (26 checks);")
print("  built-image constants disasm-verified (.qwen/tmp/ccs2_re/verify_qca.py).")
