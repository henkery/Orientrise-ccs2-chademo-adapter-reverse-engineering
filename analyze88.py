#!/usr/bin/env python3
"""analyze88 — HV measurement chain decoder (REPORT §5.21 measurement addendum).

Decodes the C013 factory-calibrated HV measurement front-end that produces outvol=get_hv()/10:
  1. SPI4 init 0x08088C38 (CR1=0x344) + NV read core 0x08088CFE (external-flash READ 0x03).
  2. NV cal lazy-init 0x0805231E (magic/checksum validation) + checksum 0x0805236A + get_hv
     0x08052770 (two-point interpolation, field offsets).
  3. ADC init 0x08088584 (ADC1+ADC2 regular-simultaneous, DMA2 stream0, TIM8 trigger).
  4. DMA ISR 0x080886BC + accumulator 0x08088748 (differential sum, 3125 events -> live_raw).

Key finding: the factory cal lives in an EXTERNAL 2 MB SPI flash on SPI4 (CS=PE11), offset
0xFE000 — NOT STM32 internal flash. App flashing only writes internal sectors 5-9, so the
custom app reads the stock cal directly. live_raw is the accumulated sum(ADC1-ADC2) over
25000 differential samples; get_hv interpolates it (no Vrefint cal on this path — the
Vrefint-calibrated read 0x0808883A feeds the separate power-stage monitor, thresholds 8000/10500).

TB=0x0801FBFE (true link base, §5.16). LDR-literal pool alignment uses the RUNTIME PC
(base ≡ 2 mod 4); both T1 (h1&0xF800==0x4800) and T2 wide (h1&0xFF7F==0xF85F, U=bit7) forms.
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
    h1 = u16(o)
    if (h1 & 0xF800) == 0x4800:                      # LDR-literal T1
        p = (((rt(o)+4) & ~3) - TB) + (h1 & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    if (h1 & 0xFF7F) == 0xF85F and o+4 <= N:         # LDR-literal T2 wide
        U = (h1 >> 7) & 1; imm12 = u16(o+2) & 0xFFF
        base = ((rt(o)+4) & ~3)
        p = (base + imm12 if U else base - imm12) - TB
        if 0 <= p and p+4 <= N: return u32(p)
    return None

def dump(addr, n, label, stop=True):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins:
            print(f"  f+0x{a:05x}: <no disasm>"); a += 2; continue
        i = ins[0]; w = pool(a); extra = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " PERIPH" if 0x40000000 <= w < 0x60000000 else "")
            extra = f"  ; =0x{w:08X}{tag}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{extra}")
        a += i.size
        if stop and i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if stop and i.mnemonic == 'pop' and 'pc' in i.op_str: break

print("################ HV MEASUREMENT CHAIN (C013, §5.21) ################")
dump(0x08088C38, 18, "SPI4 init (CR1 0x304 -> 0x344: mode0/master//2/8bit/MSB/SSM+SSI/SPE)")
dump(0x08088CFE, 14, "NV read core: range check [src,src+len) < 0x200000 (2 MB)")
dump(0x08088D14, 46, "NV read core: CS=PE11 assert, READ 0x03 + 24-bit addr, clock out len, deassert")
dump(0x0805231E, 24, "NV cal lazy-init: read 0x44 @0xFE000, magic 0x41444A67@+0x3C, [+0x38]!=0, checksum")
dump(0x0805236A, 12, "NV cal checksum: additive sum of r1 WORDS (0x10=16 words=0x40 bytes) vs +0x40")
dump(0x08052770, 20, "get_hv: eng_lo + (live_raw-raw_lo)(eng_hi-eng_lo)/(raw_hi-raw_lo)")
dump(0x08088584, 96, "ADC init: ADC1 ch8 x8 / ADC2 ch9 x8 simultaneous, DMA2 stream0, TIM8 125kHz")
dump(0x080886BC, 40, "DMA ISR: HTIF0->words0..7 / TCIF0->words8..15, diff sum -> accumulator")
dump(0x08088748, 14, "accumulator: cal+0x2c += diff; count cal+8 to 0xC35(3125) -> b.w set_live_raw")

print("\n################ DECODED MECHANISM SUMMARY ################")
print("""
Factory cal source (KEY):
  External 2 MB SPI flash on SPI4 (0x40013400), CS = PE11 (active-low, GPIOE BSRR).
  SPI4 CR1 = 0x344 (CPOL=0/CPHA=0 mode0, master, BR=/2 -> 42 MHz, 8-bit, MSB, SSM+SSI, SPE).
  READ command 0x03 + 24-bit address (MSB first) + dummy-0x00 clocks. Cal record @ 0xFE000.
  Untouched by app flashing (internal sectors 5-9 only) -> custom app reads stock cal directly.

NV cal record (0x44 bytes = 17 words), validation (lazy-init 0x0805231E):
  word15 (+0x3C) == magic 0x41444A67 ; word14 (+0x38) != 0 ;
  checksum = sum(words[0..15]) (16 WORDS = 0x40 bytes) == word16 (+0x40).
  get_hv fields (32-bit signed): raw_hi=+0x0C, raw_lo=+0x10, eng_hi=+0x14, eng_lo=+0x18.

ADC front-end (init 0x08088584), all values byte-derived:
  ADC1 0x40012000: CR1=0x800 (discontinuous 1/trigger), CR2=0x1E000001 (ADON+EXTSEL14 TIM8_TRGO
    +rising), SMPR1=0x04924924 SMPR2=0x24924924, SQR1/2/3=0x00742108/0x10842108/0x10842108 (8x ch8=PB0).
  ADC2 0x40012100: same CR1/CR2/SMPR, SQR1/2/3=0x0074A529/0x1294A529/0x1294A529 (8x ch9=PB1).
  ADC common CCR=0x2A006: MULTI=6 regular-simultaneous ADC1+ADC2, DMA mode2 (32-bit CDR), ADCPRE=/6 (14 MHz).
  DMA2 stream0 ch0: CR=0x5518 (circular,32-bit,MINC,TCIE+HTIE), NDTR=16, PAR=ADC_CDR(0x40012308), M0AR=buf.
  TIM8 0x40010400: PSC=0 ARR=0x53F(1343) CR2=0x20(TRGO=update) CR1=0x95 -> 168MHz/1344 = 125 kHz trigger.

DSP (DMA ISR 0x080886BC + accumulator 0x08088748):
  Per half-buffer (8 dual-samples): diff = sum(ADC1 low16) - sum(ADC2 high16)  (PB0 - PB1).
  Accumulate; after 3125 half-buffer events (= 25000 samples, ~200 ms) live_raw = accumulated sum.
  live_raw global = 0x200008B0 (set via tail-branch b.w 0x08052764, NOT bl — hence no BL xref).

get_hv (0x08052770): eng_lo + (live_raw-raw_lo)*(eng_hi-eng_lo)/(raw_hi-raw_lo)  [smull+__aeabi_ldivmod].
outvol = get_hv()/10 (volts) -> context p[+0x16]. NO Vrefint cal on this path.
Separate path: Vrefint-calibrated read 0x0808883A = raw[cal+0xC]*cal+2/16380 feeds power-stage
monitor 0x080524FC (thresholds 8000/10500 ~= 800/1050 V); Vrefint factors 162981000/vref, 180180000/vref.
""")
