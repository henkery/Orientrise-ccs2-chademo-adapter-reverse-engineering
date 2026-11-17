"""Corrected comprehensive const/xref scanner for the decoded Orientrise image.
Fixes hs5.py's LDR-literal T2 U-bit bug (U is bit7, mask 0xFF7F) and keeps its
good additions (LDR T1, ADR T1/T3). Queries CAN1/CAN2 bases to test REPORT §5.8's
'bases live in a handle table, no absolute code loads' claim.
Run: nix-shell -p python3 python3Packages.capstone --run 'python3 corrected_xref.py'"""
import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
FW='/home/iroha/projects/orientrise charge adapter/re/firmware.bin'
dec=open(FW,'rb').read(); n=len(dec); BASE=0x08020000
md=Cs(CS_ARCH_ARM,CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN); md.detail=True
def imm16(h1,h2): return (((h1>>4)&0xF)<<12)|(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
def ror32(v,r): r&=31; return ((v>>r)|(v<<(32-r)))&0xFFFFFFFF if r else v
def thumb_expand_imm(imm12):
    if (imm12&0xC00)==0:
        op=(imm12>>8)&3; b=imm12&0xFF
        return [b,(b<<16)|b,(b<<24)|(b<<8),(b<<24)|(b<<16)|(b<<8)|b][op]
    return ror32(0x80|(imm12&0x7F),(imm12>>7)&0x1F)

# const(value loaded) -> sites ; adr(address formed) -> sites
const=collections.defaultdict(list); adr=collections.defaultdict(list)
last={}
for a in range(0x400,n-4,2):
    h1=struct.unpack_from('<H',dec,a)[0]; h2=struct.unpack_from('<H',dec,a+2)[0]
    if (h1&0xFBF0)==0xF240: last[(h2>>8)&0xF]=(a,imm16(h1,h2))
    elif (h1&0xFBF0)==0xF2C0:
        rd=(h2>>8)&0xF
        if rd in last:
            pa,lo=last[rd]
            if a-pa<=12: const[(imm16(h1,h2)<<16)|lo].append(('movw/movt',pa))
            del last[rd]
    # MOV/MOVS immediate T2 (rotated byte) — e.g. mov.w rX,#0x40000000
    if (h1&0xFBEF)==0xF04F:
        imm12=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
        const[thumb_expand_imm(imm12)].append(('mov-imm',a))
    # LDR literal T2 — CORRECT: U=bit7, mask 0xFF7F (accepts 0xF85F & 0xF8DF only)
    if (h1&0xFF7F)==0xF85F:
        u=(h1>>7)&1
        t=((a+4)&~3)+((h2&0xFFF) if u else -(h2&0xFFF))
        if 0<=t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldrT2',a))
    # LDR literal T1 — 01001 Rt imm8, always forward
    if (h1&0xF800)==0x4800:
        t=((a+4)&~3)+(h1&0xFF)*4
        if t<n-3: const[struct.unpack_from('<I',dec,t)[0]].append(('ldrT1',a))
    # ADR T1 — 10100 Rd imm8, forward; target is an ADDRESS (virtual)
    if (h1&0xF800)==0xA000:
        t=((a+4)&~3)+(h1&0xFF)*4
        if t<n: adr[BASE+t].append(('adrT1',a))
    # ADR T3 add/sub (ADDW/SUBW Rd=PC)
    if (h1&0xFBFF)==0xF20F:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
        t=((a+4)&~3)+imm
        if t<n: adr[BASE+t].append(('adrT3+',a))
    elif (h1&0xFBFF)==0xF2AF:
        imm=(((h1>>10)&1)<<11)|(((h2>>12)&7)<<8)|(h2&0xFF)
        t=((a+4)&~3)-imm
        if 0<=t<n: adr[BASE+t].append(('adrT3-',a))

def sites(v):
    return ", ".join(f"{k}@f+0x{o:06x}" for k,o in const.get(v,[])[:16]) or "(none)"

print("== Peripheral BASE constants loaded in code (corrected scanner) ==")
for v,l in [(0x40006400,"CAN1"),(0x40006800,"CAN2"),(0x40023800,"RCC"),
            (0x40013000,"SPI1"),(0x40000000,"TIM2"),(0x40012000,"ADC1"),
            (0x40007000,"PWR"),(0xE0042000,"DBGMCU")]:
    print(f"  {l:7s} 0x{v:08x}: {sites(v)}")

print("\n== Raw 32-bit occurrences of CAN1/CAN2 base (data tables incl.) ==")
for v,l in [(0x40006400,"CAN1"),(0x40006800,"CAN2")]:
    offs=[o for o in range(0,n-3) if struct.unpack_from('<I',dec,o)[0]==v]
    print(f"  {l}: "+", ".join(f"f+0x{o:06x}({'4B' if o%4==0 else '2B' if o%2==0 else 'odd'})" for o in offs[:20]))

print("\n== Disasm around any CAN-base code load (if present) ==")
for v in (0x40006400,0x40006800):
    for k,o in const.get(v,[]):
        print(f"--- {k} loading 0x{v:08x} @ f+0x{o:06x} ---")
        for i in md.disasm(dec[o:o+24],BASE+o):
            print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}")