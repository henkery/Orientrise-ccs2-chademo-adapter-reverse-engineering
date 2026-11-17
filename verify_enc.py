"""Empirically determine the LDR(literal) T2 U-bit position and test both scanner masks.
Run: nix-shell -p python3 python3Packages.capstone --run 'python3 verify_enc.py'"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

def dis(hw1, hw2, addr=0x08020400):
    b = struct.pack('<HH', hw1, hw2)
    out = [f"{i.mnemonic} {i.op_str}" for i in md.disasm(b, addr)]
    return out[0] if out else "(invalid / not decoded)"

print("== Crafted 32-bit halfword pairs, disassembled by capstone (addr=0x08020400) ==")
print("   hw1     hw2     -> disassembly")
for hw1 in (0xF85F, 0xF8DF, 0xF95F, 0xF9DF, 0xFC5F, 0xFCDF):
    print(f"  0x{hw1:04X}  0x0010  -> {dis(hw1, 0x0010)}")

print("\n== LDR literal T1 (0x4800|Rt<<8|imm8) and ADR T1 (0xA000|Rd<<8|imm8) ==")
print(f"  0x4808 (ldr r0,[pc,#32]) -> {dis(0x4808, 0x0000)}")
print(f"  0xA008 (adr r0,pc+32)    -> {dis(0xA008, 0x0000)}")

print("\n== Which hw1 each mask accepts, and the U bit it reads ==")
cands = [0xF85F, 0xF8DF, 0xF95F, 0xF9DF, 0xFC5F, 0xFCDF]
for label, mask, ubit in (("analyze27/34", 0xFF7F, 7), ("hs5 'corrected'", 0xFB7F, 10)):
    acc = [f"0x{h:04X}(u={(h>>ubit)&1})" for h in cands if (h & mask) == 0xF85F]
    print(f"  {label:16s} mask=0x{mask:04X} U=bit{ubit}: accepts {', '.join(acc) or '(none)'}")

print("\n== Ground truth from capstone for a REAL forward pool load ==")
# Search firmware for a known forward LDR-literal and show capstone's rendering.
dec = open('/home/iroha/projects/orientrise charge adapter/re/firmware.bin','rb').read()
n=len(dec); shown=0
for a in range(0x400, n-4, 2):
    h1=struct.unpack_from('<H',dec,a)[0]; h2=struct.unpack_from('<H',dec,a+2)[0]
    if h1 in (0xF85F,0xF8DF) and (h2&0xFFF)>0:
        print(f"  f+0x{a:06x}: hw1=0x{h1:04X} hw2=0x{h2:04X} -> {dis(h1,h2,0x08020000+a)}")
        shown+=1
        if shown>=6: break