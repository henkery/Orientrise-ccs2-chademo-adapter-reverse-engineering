#!/usr/bin/env python3
"""analyze95.py — CP/PP analog front-end (REPORT §5.9, Agent I ADC3 + Agent J TIM4).

Re-derives from the C013 firmware bytes the GATED CP/PP analog acquisition front-end that feeds
the CP/PP signaling logic (cp.c, analyze92) and the charge-stm plug-in input. Replicated INERT in
custom_fw (measurement only — NO power-stage GPIO). Two independent measurement paths:

  (J) CP PWM TIM4 INPUT-CAPTURE on PD12 (AF2 TIM4_CH1) — duty + period.  [src/cp_capture.c]
  (I) PP/CPD ADC3 analog acquisition + PD11/D_LINK digital reads.       [Agent I — see below]

=============================================================================================
(J) CP PWM TIM4 input-capture (VERIFIED byte-exact; replicated in src/cp_capture.c, host-tested
    test_cp_capture.c 42 checks; disasm-verified verify_ccs2.py).
=============================================================================================
  TIM4 init   0x08088A8C (called from main 0x0808822A). Register writes IN ORDER (no EGR/UG):
    DIER=0; SR=0; CR1=0; PSC=83(0x53); ARR=1110(0x456); SMCR=0x54; CCMR1=0x201; CCMR2=0;
    CCR3=1100(0x44C); CCER=0x13; SR=0; DIER=0x0A; CR1=0x81. Then zero CP struct 0x200009F8
    (median count[+3], deglitch state[+2], raw word 0x20000A08).
    PSC=83 -> 84 MHz/(83+1) = 1 MHz -> 1 us/tick. ARR=1110 free-run overflow. SMCR=0x54 =
    SMS=100 reset mode, TS=101 TI1FP1 -> CNT resets on PD12 falling edge. CCMR1=0x201 =
    CC1S=01 (CH1 direct TI1) + CC2S=10 (CH2 indirect TI1), no filter/prescaler. CCER=0x13 =
    CC1E|CC1P (CH1 falling) + CC2E (CH2 rising). CCR3=1100 output-compare frozen -> CC3IF
    heartbeat when no edge. DIER=0x0A = CC1IE|CC3IE. CR1=0x81 = CEN|ARPE.
  RCC/GPIO  SystemInit 0x08087BEA: AHB1ENR=0x0074101F (GPIOD bit3), APB1ENR=0x1200003F (TIM4
    bit2). GPIOD init 0x08087A98: MODER=0x0241004A (PD12 bits25:24=10 AF), AFRH=0x20000 (PD12
    nibble=2 AF2 TIM4_CH1), PUPDR=0x01280005 (PD12 pull-up). CP input inverted on PD12 [inferred].
  vector    Stock vector table is a FLASH template 0x080B1B8C copied to RAM VTOR=0x20000000
    (set 0x08087AF4 via lsls r3,r0,#0x15 from NVIC base 0xE000E100). TIM4 vec[46] @ f+0x92046
    = 0x08088ACF -> ISR 0x08088ACE. NVIC ISER0=0x78D80402 (bit30 TIM4_IRQn30) @ 0x08087B8E.
    (The flash 0x08020000 holds only SP+Reset+startup code; f+0x4BA is NOT a vector.)
  TIM4 ISR    0x08088ACE: snapshot SR, clear SR=0.
    UIF (bit0) overflow/no-edge -> read GPIOD_IDR bit12: PD12 high -> duty 0 / low -> duty 1000,
      period 0, hold-flag=1.
    CC1IF&CC2IF ((SR>>1)&3==3) -> CCR1=period us, CCR2=PD12 low-time. Validity (CCR1-950)<=100
      (CCR1 in [950,1050] ~952-1053 Hz) && CCR2<=CCR1. hold set -> re-publish last globals +
      clear hold; else duty = 1000*CCR2/CCR1 (muls+udiv, PER-MILLE = percent x10), period=CCR1.
      Invalid -> duty 0, period=CCR1, hold=1.
    publish(duty,period) -> change-detect store globals duty[0x20000A00]/period[0x200009FE],
      changed flag[0x200009F8]=1, update counter[0x20000A04]++.
  publish     0x08088A20: median insert/extract -> store raw word 0x20000A08 if >0. DC deglitch
    state machine on RAW duty: state0 duty0->state1/cnt1, duty1000->state2/cnt1, intermediate->
    state UNCHANGED; state1 duty!=0->state0, duty0 cnt++ >=128(0x80) -> force raw duty0; state2
    duty!=1000->state0, duty1000 cnt++ >=32(0x20) -> force raw duty1000. Forced raw word uses
    the ARG period. No-PWM timeout ~128x1.11ms=142ms (duty0) / 32x1.11ms=36ms (duty1000).
  median      0x08088B9E: buf 0x200226E0[16] (lo=duty hi=period), insertion-sort ascending by
    duty; count[0x200009FB] reaches 16 -> scan i=8..15 first window buf[i].duty-buf[i-8].duty
    <=15(0xF) -> middle buf[i-4]; mid duty 0/1000 -> reject (return -1); else return mid word;
    reset count. -O2 stock uses cmp #0x80/#0x20 for the deglitch thresholds.
  getters     duty 0x08088B58 = ldrh[0x20000A00]; period 0x08088B6C = ldrh[0x200009FE] (NO Hz
    conversion — period us, f_Hz=1e6/period implicit); changed 0x08088B60 rd-clr[0x200009F8];
    update 0x08088B92 [0x20000A04]; PD11 0x08088B88 = GPIOD_IDR bit11.
  consumers   CP_ST 0x08052914 reads duty getter (duty0->'E', PD11!=0->'C', else 'B'); duty-char
    0x08052804 ([30,70]->'5' ISO15118 HLC); duty->IEC-current 0x08052838 (corroborates per-mille);
    DIN session reads period via cp_getfreq 0x08052892 (0x080381EA/240/268) as the cadence divisor.
  KEY CORRECTIONS vs prior B/F reports: 0x200009FE is PERIOD us (raw CCR1) NOT Hz; 0x200009F8 is
    the CP capture struct (NOT protocol-config); duty is per-mille (1000*CCR2/CCR1); the vector
    table is RAM VTOR (template 0x080B1B8C), not flash 0x08020000.

=============================================================================================
(I) PP/CPD/BAT ADC3 analog acquisition + PD11/D_LINK reads (VERIFIED byte-exact; replicated in
    src/cp_adc.c, host-tested test_cp_adc.c 42 checks; disasm-verified verify_ccs2.py).
=============================================================================================
  Sole ADC init 0x08088584 (called from bringup 0x080881F8) configures BOTH the HV path
    (ADC1+ADC2 ch8/ch9 PB0/PB1, DMA2 Stream0 — see adc.c / analyze88) AND the CP/PP path
    (ADC3 + DMA2 Stream1, block @0x08088628). They SHARE TIM8 TRGO + the ADC common clock.
  TIM8        0x080886A2: PSC=0, ARR=0x53F(1343), SR=0, DIER=0, CR2=0x20 (MMS=update->TRGO),
    CR1=0x95 (CEN|URS|DIR down|ARPE) -> 168 MHz/1344 = 125 kHz TRGO (8 us). Owned by adc.c.
  ADC3        0x40012200 (block 0x08088628): CR1=0, CR2=0, SR=0; SMPR1=0x04924924,
    SMPR2=0x24924924 (84-cycle sampling ALL channels -> 96-cycle conv = 6.857 us < 8 us);
    SQR1=0x00700581 (L=7 -> 8 conv), SQR2=0x04110401, SQR3=0x18110441 ->
    sequence SQ1..8 = [ch1, ch2, ch1, ch2, ch1, ch12, ch1, ch0]; CR1=0x800 (DISCEN, ONE
    conversion per trigger, NOT SCAN), CR2=0x1E000301 (ADON|DMA bit8|DDS bit9|EXTSEL=14
    TIM8_TRGO|EXTEN rising). Pins (MODER-proven analog): ch1=PA1, ch2=PA2, ch12=PC2, ch0=PA0.
    ADC_CCR=0x0002A006: MULTI=6 (ADC12 regular-simultaneous, inert for ADC3), DMA mode2,
    ADCPRE=/6 -> 84 MHz/6 = 14 MHz ADC clock; TSVREFE=0 (NO Vrefint in C013), VBATE=0.
  DMA2 S1     Channel2 (0x40026428): CR=0 wait EN clear; LIFCR=0xF40; NDTR=16 halfwords;
    PAR=0x4001224C (ADC3_DR); M0AR=0x20022680; FCR=0; CR=0x04002D10 (CHSEL=2|halfword x
    halfword|MINC|CIRC|TCIE bit4, HTIE=0) then |=1. TC every 16 conv = 2 sequences = 128 us.
  vector      RAM VTOR template 0x080B1B8C: IRQ57 vec @ f+0x920B2 = 0x0808876B -> ISR
    0x0808876A (IRQ56 HV vec @ f+0x920AE = 0x080886BD). NVIC ISER1=0x03800000 (IRQ55/56/57),
    priority byte 0x60 @ 0xE000E439 (PRIGROUP=2).
  ISR         0x0808876A: snapshot DMA2_LISR, clear LIFCR=0xF40. TCIF1 (bit11) set -> sum the
    SECOND buffer half (buf+0x10..+0x1E = SQ1..8 of the 2nd sequence); HTIE=0 so the first-half
    mirror (offsets 0x00..0x0E) is defensive dead code. Per event:
      r5    = ch1_SQ1 + ch1_SQ3 + ch1_SQ5 + ch1_SQ7  (4*ch1, PA1)
      accA += ch2_SQ2 + ch2_SQ4                       (2*ch2, PA2)   [+0x14]
      accB += ch12_SQ6                                (ch12, PC2)    [+0x1C]
      accC += ch0_SQ8                                 (ch0, PA0)     [+0x24]
    counter[+0]++ ; every 8 TC events (= 1.024 ms) publish:
      PP  raw[0x200009D0] = accA = 16*sum(ch2)   (8 events x 2*ch2)
      BAT raw[0x200009D8] = accB = 8*sum(ch12)
      CPD raw[0x200009E0] = accC = 8*sum(ch0)
    then clear accA/accB/accC + counter. r5 (4*ch1) is stored EVERY event to [+0x0C] (the
    calibrated "+24V" rail byproduct) and feeds a power-fail hysteresis (low 8664 / high 9578,
    queue 0x200009F0) — a SEPARATE subsystem, NOT folded into PP.
  *** CORRECTION to Agent I's summary "PP = 32*sum(ch1) + 16*sum(ch2)" ***: the ISR bytes
    accumulate ONLY 2*ch2 into accA (the `add r3,r6` at 0x0808879C/0x080887BE is fed by
    ch2_SQ2+ch2_SQ4); r5=4*ch1 is NEVER added to accA — it goes to the [+0x0C] byproduct store
    (0x0808880E). So PP = 16*sum(ch2) (PA2 ALONE), which cleanly matches divisor 65520=16*4095
    (the awkward "3x pin-mV of a 2:1 ch1/ch2 mean" interpretation was an artifact of the misread).
  getters     load pool 0x200009C0 @ f+0x68CAE (shared ADC struct base):
    AD_PP  0x08088850 = [base+0x10] * 3300 / 65520  (65520 = 16*4095)  -> 3300*avg_ch2/4095 mV
    AD_BAT 0x08088864 = [base+0x18] * 6600 / 32760  (32760 = 8*4095)   -> 6600*avg_ch12/4095 mV
    AD_CPD 0x08088878 = [base+0x20] * 3300 / 32760                    -> 3300*avg_ch0/4095 mV
    (mV, integer udiv truncation, no cal/filter — filtering lives in the ISR.)
    NAMING CORRECTION: 0x08088864 is AD_BAT (firmware dumper label "AD_BAT : %.3u" @0x0804F79C),
    NOT "CP analog". The +24V getter 0x0808883A = cal*[+0x0C]/16380 (cal default 18810 from the
    SPI4 page-2 record; power-fail thresholds 162981000/cal=8664, 180180000/cal=9578).
  D_LINK      0x080884BA = GPIOB_IDR bit12 (PB12 IN pull-down, PLC modem link; filterless leaf).
  PD11        0x08088B88 = GPIOD_IDR bit11. PD11 is an OUTPUT (MODER bits23:22=01) driven by BCB
    0x080528DC (BSRR bit11, 'B'->0/'C'->1); CP_ST 0x08052914 reads it back (duty0->'E',
    PD11!=0->'C', else 'B'). The replica only READS PD11 — the BCB drive stays GATED.
  consumers   AD_PP -> PP-plug debounce 0x080527B0 (<=2146 mV x4 plugged / >=2296 mV x4 unplugged);
    AD_CPD -> CHAdeMO STM cable-check states (cmp #2 mV gate); AD_BAT -> dumper only.
  boundary    C013 has NO Vrefint-calibrated layer (TSVREFE=0); the HV power-stage monitor is the
    separate ADC1+ADC2 ch8/ch9 differential DMA2 Stream0 path (adc.c). The inert CP/PP replica
    needs only ADC3 ch0/1/2/12 + TIM8 TRGO + DMA2 Stream1 + the ISR sum/publish + the 3 getters;
    the power-fail hysteresis/queue + SPI4 cal "+24V" scaling are dropped (separate subsystem).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze95.py'
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
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr-TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: print(f"  f+0x{a:05x}: <none>"); a += 2; continue
        i = ins[0]; w = pool(a); ex = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " PERIPH" if 0x40000000 <= w < 0x40100000 else "")
            ex = f"  ; =0x{w:08X}{tag}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:9s} {i.op_str}{ex}")
        a += i.size
        if stop and i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if stop and i.mnemonic == 'pop' and 'pc' in i.op_str: break

def imms(addr, n):
    a = addr - TB; vals = set(); movw = {}; mn = []
    for _ in range(n):
        ins = dis(a)
        if not ins: break
        i = ins[0]; mn.append(i.mnemonic.split('.')[0])
        for op in i.operands:
            if op.type == 2: vals.add(op.imm & 0xFFFFFFFF)
        if i.mnemonic in ('movw', 'movt') and len(i.operands) == 2:
            r = i.operands[0].reg; im = i.operands[1].imm & 0xFFFF
            if i.mnemonic == 'movw': movw[r] = im; vals.add(im)
            elif r in movw: vals.add((im << 16) | movw[r])
        w = pool(a)
        if w is not None: vals.add(w); vals.add(w & 0xFFFF); vals.add((w >> 16) & 0xFFFF)
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break
    return vals, mn

checks = failures = 0
def check(cond, msg):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1; print("FAIL:", msg)

print("################ CP/PP ANALOG FRONT-END (§5.9, byte-exact, C013) ################")

print("\n#### (J) TIM4 init 0x08088A8C (PD12 AF2 TIM4_CH1 input capture) ####")
dump(0x08088A8C, 40, "TIM4 init 0x08088A8C", stop=False)
v, _ = imms(0x08088A8C, 40)
for c, lab in [(0x53, 'PSC=83'), (0x456, 'ARR=1110'), (0x54, 'SMCR=0x54'), (0x201, 'CCMR1=0x201'),
               (0x44C, 'CCR3=1100'), (0x13, 'CCER=0x13'), (0x0A, 'DIER=0x0A'), (0x81, 'CR1=0x81'),
               (0x40000800, 'TIM4 base')]:
    check(c in v, f"TIM4 init carries {lab}")

print("\n#### (J) GPIOD PD12 AF2 config 0x08087A98 ####")
dump(0x08087A98, 16, "GPIOD init 0x08087A98 (PD12 AF2)", stop=False)
vg, _ = imms(0x08087A98, 24)
check(0x0241004A in vg, "GPIOD MODER=0x0241004A (PD12 AF)")
check(0x20000 in vg, "GPIOD AFRH=0x20000 (PD12 AF2)")
check(((0x0241004A >> 24) & 3) == 2 and ((0x20000 >> 16) & 0xF) == 2, "PD12 MODER=AF, AFRH=2")

print("\n#### (J) TIM4 ISR 0x08088ACE (duty=1000*CCR2/CCR1, validity, overflow PD12) ####")
dump(0x08088ACE, 80, "TIM4 ISR 0x08088ACE", stop=False)
v, mn = imms(0x08088ACE, 80)
for c, lab in [(0x3E8, 'duty x1000 / full 1000'), (0x3B6, 'validity CCR1-950'), (0x64, 'validity span 100'),
               (0x40020C00, 'GPIOD base (overflow PD12 read)')]:
    check(c in v, f"ISR carries {lab}")
check('muls' in mn and 'udiv' in mn, "ISR duty = muls + udiv (1000*CCR2/CCR1 per-mille)")

print("\n#### (J) publish/deglitch 0x08088A20 (zero 128 / full 32) ####")
dump(0x08088A20, 60, "publish/deglitch 0x08088A20", stop=False)
v, _ = imms(0x08088A20, 60)
check(0x80 in v, "deglitch zero threshold 128 (0x80)")
check(0x20 in v, "deglitch full threshold 32 (0x20)")
check(0x3E8 in v, "deglitch full-scale 1000 (0x3E8)")

print("\n#### (J) median filter 0x08088B9E (16-sample median-of-9 span<=15) ####")
dump(0x08088B9E, 120, "median 0x08088B9E", stop=False)
v, _ = imms(0x08088B9E, 120)
check(0x10 in v, "median batch 16 (0x10)")
check(0xF in v, "median cluster span <=15 (0xF)")
check(0x200226E0 in v, "median buffer 0x200226E0")

print("\n#### (J) getters + vector table + VTOR/NVIC ####")
dump(0x08088B58, 6, "duty getter 0x08088B58 ([0x20000A00])")
dump(0x08088B6C, 6, "period getter 0x08088B6C ([0x200009FE], us NOT Hz)")
dump(0x08088B88, 6, "PD11 getter 0x08088B88 (GPIOD IDR bit11)")
vec46 = u32(0x92046)
print(f"\n  TIM4 vec[46] @ f+0x92046 = 0x{vec46:08X}")
check(vec46 == 0x08088ACF, "TIM4 vector word = 0x08088ACF (ISR 0x08088ACE|1)")
vt, _ = imms(0x08087AE6, 80)
check(0x78D80402 in vt and ((0x78D80402 >> 30) & 1), "NVIC ISER0=0x78D80402 bit30 TIM4 enabled")

print("\n#### (J) CP_ST 0x08052914 consumes duty getter ####")
dump(0x08052914, 20, "CP_ST 0x08052914", stop=False)
a = 0x08052914 - TB; bl = []
for _ in range(24):
    ins = dis(a)
    if not ins: break
    i = ins[0]
    if i.mnemonic == 'bl':
        try: bl.append(int(i.op_str.replace('#', ''), 0))
        except ValueError: pass
    a += i.size
check(0x08088B58 in bl, "CP_ST calls duty getter 0x08088B58")
check(0x08088B88 in bl, "CP_ST calls PD11 getter 0x08088B88")

print("\n== RESOLVED CP PWM TIM4 capture (C013, Agent J) ==")
print("  PD12 AF2 TIM4_CH1 input capture, PSC=83 (1us/tick), ARR=1110, SMCR=0x54 reset-on-TI1FP1,")
print("  CCMR1=0x201 (CH1 falling direct + CH2 rising indirect), CCR3=1100 heartbeat, CCER=0x13,")
print("  DIER=0x0A (CC1IE|CC3IE), CR1=0x81. ISR 0x08088ACE: duty=1000*CCR2/CCR1 (per-mille),")
print("  period=CCR1 (us, NOT Hz), validity CCR1 in [950,1050] && CCR2<=CCR1; overflow reads PD12")
print("  (high->duty0/low->duty1000). publish 0x08088A20 median-of-9 (span<=15) + DC deglitch")
print("  (0 needs 128, 1000 needs 32). globals duty[0x20000A00]/period[0x200009FE]. RAM VTOR")
print("  vector template 0x080B1B8C vec[46]=0x08088ACF, NVIC ISER0 bit30. Replicated INERT in")
print("  src/cp_capture.c (measurement only, NO power GPIO; PD12 RMW preserves gpio_safe states).")
print("  CORRECTIONS: 0x200009FE=period us not Hz; 0x200009F8=CP capture struct; duty per-mille.")

# =============================================================================================
# (I) PP/CPD/BAT ADC3 analog acquisition + PD11/D_LINK reads
# =============================================================================================
def ldr_offs(addr, n):
    a = addr - TB; offs = []
    for _ in range(n):
        ins = dis(a)
        if not ins: break
        i = ins[0]
        if i.mnemonic in ('ldr', 'ldrh') and len(i.operands) == 2 and i.operands[1].type == 3:
            offs.append((i.mnemonic, i.operands[1].mem.disp))
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break
    return offs

def ubfx_bit(addr, n, bit):
    a = addr - TB
    for _ in range(n):
        ins = dis(a)
        if not ins: break
        i = ins[0]
        if i.mnemonic == 'ubfx' and len(i.operands) == 4:
            if i.operands[2].imm == bit and i.operands[3].imm == 1: return True
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
    return False

print("\n#### (I) ADC3 getters 0x08088850 / 0x08088864 / 0x08088878 (pool 0x200009C0) ####")
for g, lab in [(0x08088850, 'AD_PP'), (0x08088864, 'AD_BAT'), (0x08088878, 'AD_CPD')]:
    dump(g, 8, lab + ' getter')
pw = u32(0x68CAE)
print(f"\n  getter pool f+0x68CAE = 0x{pw:08X}")
check(pw == 0x200009C0, "getter pool base = 0x200009C0 (shared ADC struct)")
vp, _ = imms(0x08088850, 8); vb, _ = imms(0x08088864, 8); vc, _ = imms(0x08088878, 8)
check(0xCE4 in vp and 0xFFF0 in vp, "AD_PP x3300/65520 (0xCE4/0xFFF0)")
check(0x19C8 in vb and 0x7FF8 in vb, "AD_BAT x6600/32760 (0x19C8/0x7FF8)")
check(0xCE4 in vc and 0x7FF8 in vc, "AD_CPD x3300/32760 (0xCE4/0x7FF8)")
check(0x10 in [o for _, o in ldr_offs(0x08088850, 8)], "AD_PP reads base+0x10 (0x200009D0)")
check(0x18 in [o for _, o in ldr_offs(0x08088864, 8)], "AD_BAT reads base+0x18 (0x200009D8)")
check(0x20 in [o for _, o in ldr_offs(0x08088878, 8)], "AD_CPD reads base+0x20 (0x200009E0)")

print("\n#### (I) ADC3 + DMA2 Stream1 init block 0x08088628 (full fn 0x08088584) ####")
dump(0x08088628, 70, "ADC3+DMA2_S1 init 0x08088628", stop=False)
vi, _ = imms(0x08088584, 220)   # full init: CP/PP block reuses HV-block regs (SMPR/CR1/NDTR)
for c, lab in [(0x0002A006, 'ADC_CCR=0x0002A006'), (0x40012200, 'ADC3 base'),
               (0x40026400, 'DMA2 base'), (0x04002D10, 'S1CR'), (0x04924924, 'SMPR1'),
               (0x24924924, 'SMPR2'), (0x00700581, 'SQR1'), (0x04110401, 'SQR2'),
               (0x18110441, 'SQR3'), (0x1E000301, 'CR2'), (0xF40, 'LIFCR'), (0x10, 'NDTR=16'),
               (0x20022640, 'buf base 0x20022640')]:
    check(c in vi, f"ADC3 init carries {lab}")
check(0x40026400 in vi and 0x28 in vi, "DMA2_Stream1 = 0x40026400+0x28 = 0x40026428")
check(0x40012200 in vi and 0x4C in vi, "ADC3_DR PAR = 0x40012200+0x4C = 0x4001224C")
check(0x20022640 in vi and 0x40 in vi, "M0AR buf = 0x20022640+0x40 = 0x20022680")
check((0x40012200 >> 19) == 0x800 and 0x13 in vi, "CR1=0x800 DISCEN via asrs#19 of ADC base")

print("\n#### (I) TIM8 trigger init 0x080886A2 (shared 125 kHz TRGO) ####")
dump(0x080886A2, 12, "TIM8 init 0x080886A2", stop=False)
vt8, _ = imms(0x080886A2, 12)
for c, lab in [(0x40010400, 'TIM8 base'), (0x53F, 'ARR=1343'), (0x20, 'CR2 MMS=update'),
               (0x95, 'CR1 CEN|URS|DIR|ARPE')]:
    check(c in vt8, f"TIM8 init carries {lab}")

print("\n#### (I) ADC3 sequence decode (SQR1/2/3) ####")
SQR1, SQR2, SQR3 = 0x00700581, 0x04110401, 0x18110441
L = (SQR1 >> 20) & 0xF
sq = [((SQR3 >> (5*k)) & 0x1F) if k < 6 else ((SQR2 >> (5*(k-6))) & 0x1F) for k in range(8)]
print(f"  L={L} (8 conversions), sequence SQ1..8 = {sq}")
check(L == 7, "SQR1 L=7 -> 8 conversions")
check(sq == [1, 2, 1, 2, 1, 12, 1, 0], "sequence = [ch1,ch2,ch1,ch2,ch1,ch12,ch1,ch0]")
check(sq.count(1) == 4 and sq.count(2) == 2 and sq.count(12) == 1 and sq.count(0) == 1,
      "weights ch1x4 ch2x2 ch12x1 ch0x1 per sequence")
check(65520 == 16*4095 and 32760 == 8*4095, "divisor identities 65520=16*4095 / 32760=8*4095")

print("\n#### (I) CP/PP ISR 0x0808876A (IRQ57) — accumulation + PP-excludes-ch1 CORRECTION ####")
dump(0x0808876A, 90, "ISR 0x0808876A", stop=False)
vs, _ = imms(0x0808876A, 90)
for c, lab in [(0x40026400, 'DMA2 base'), (0xF40, 'LIFCR clear'), (0x200009C0, 'struct base'),
               (0x8, 'publish every 8')]:
    check(c in vs, f"ISR carries {lab}")
check(0x20022640 in vs and 0x40 in vs, "ISR CP/PP buf = 0x20022640+0x40 = 0x20022680")
sh = {o for m, o in ldr_offs(0x0808876A, 90) if m == 'ldrh' and 0x10 <= o <= 0x1E}
check({0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E} <= sh,
      "ISR reads second-half SQ1..8 at +0x10..+0x1E")
# Structural dataflow trace: accA (r3) accumulates ONLY ch2_SQ2+ch2_SQ4; r5 (4*ch1) -> +0xC only.
a = 0x0808876A - TB; seqi = []
for _ in range(90):
    ins = dis(a)
    if not ins: break
    i = ins[0]; seqi.append((TB+a, i.mnemonic, i.op_str)); a += i.size
    if i.mnemonic == 'pop' and 'pc' in i.op_str: break
accA_sites = [(ad, k) for k, (ad, mn, ops) in enumerate(seqi)
              if mn == 'add' and ops == 'r3, r6' and k+1 < len(seqi)
              and seqi[k+1][1] == 'str' and seqi[k+1][2] == 'r3, [r4, #0x14]']
check([ad for ad, _ in accA_sites] == [0x0808879C, 0x080887BE],
      "accA accumulation sites = 0x0808879C (2nd half) + 0x080887BE (1st half mirror)")
for ad, idx in accA_sites:
    pre = seqi[idx-3:idx]
    o2, o4 = ('#0x12', '#0x16') if ad == 0x0808879C else ('#2', '#6')
    check(pre[0][1] == 'ldrh' and pre[0][2] == f'r6, [r0, {o2}]'
          and pre[1][1] == 'ldrh' and pre[1][2] == f'r7, [r0, {o4}]'
          and pre[2][1] == 'add' and pre[2][2] == 'r6, r7',
          f"accA source = ch2_SQ2+ch2_SQ4 (2*ch2) @0x{ad:08X} — NOT ch1")
check(any(mn == 'str' and ops == 'r5, [r4, #0xc]' and ad == 0x0808880E for ad, mn, ops in seqi),
      "4*ch1 (r5) stored to +0xC byproduct @0x0808880E (the +24V rail, NOT PP)")
check(not any(mn == 'str' and ops == 'r5, [r4, #0x14]' for ad, mn, ops in seqi),
      "r5 (4*ch1) NEVER stored to accA[+0x14] — PP excludes ch1 (CORRECTION)")
check(any(mn == 'str' and ops == 'r1, [r4, #0x10]' and ad == 0x080887E0 for ad, mn, ops in seqi),
      "PP raw[+0x10] = accA (r1) published @0x080887E0")

print("\n#### (I) D_LINK 0x080884BA (PB12) + PD11 read 0x08088B88 / write 0x08088B74 ####")
dump(0x080884BA, 6, "D_LINK 0x080884BA")
vd, _ = imms(0x080884BA, 6)
check(0x40020400 in vd and ubfx_bit(0x080884BA, 6, 12), "D_LINK = GPIOB_IDR bit12 (PB12)")
dump(0x08088B88, 6, "PD11 read 0x08088B88")
vpd, _ = imms(0x08088B88, 6)
check(0x40020C00 in vpd and ubfx_bit(0x08088B88, 6, 11), "PD11 read = GPIOD_IDR bit11")
dump(0x08088B74, 10, "PD11 write 0x08088B74 (BCB BSRR bit11 — drive GATED in replica)")

print("\n#### (I) NVIC ISER1 + vector slots IRQ56/57 ####")
vn, _ = imms(0x08087AE6, 90)
check(0x03800000 in vn and ((0x03800000 >> 25) & 1), "NVIC ISER1=0x03800000 bit25 IRQ57 enabled")
vec57 = u32(0x920B2); vec56 = u32(0x920AE)
print(f"\n  IRQ57 vec @ f+0x920B2 = 0x{vec57:08X} ; IRQ56 vec @ f+0x920AE = 0x{vec56:08X}")
check(vec57 == 0x0808876B, "IRQ57 vector = 0x0808876B (CP/PP ISR 0x0808876A|1)")
check(vec56 == 0x080886BD, "IRQ56 vector = 0x080886BD (HV ISR 0x080886BC|1)")

print("\n== RESOLVED CP/PP ADC3 analog acquisition (C013, Agent I + byte-verification) ==")
print("  ADC3 (0x40012200) CR1=0x800 DISCEN (1 conv/trigger), CR2=0x1E000301 (TIM8_TRGO rising),")
print("  SMPR 84-cycle all-ch, sequence [ch1,ch2,ch1,ch2,ch1,ch12,ch1,ch0] (PA1/PA2/PC2/PA0),")
print("  CCR=0x0002A006 ADCPRE=/6 (14 MHz), TSVREFE=0 (NO Vrefint). DMA2 Stream1 Ch2 CR=0x04002D10")
print("  NDTR=16 halfwords PAR=ADC3_DR M0AR=0x20022680, TC-only IRQ57 (vec 0x0808876B). ISR")
print("  0x0808876A sums the second half, publishes every 8 TC (1.024 ms): PP=16*sum(ch2) [PA2],")
print("  BAT=8*sum(ch12) [PC2], CPD=8*sum(ch0) [PA0]; getters x3300/65520, x6600/32760, x3300/32760.")
print("  CORRECTION: PP accumulates ONLY 2*ch2/event (accA); 4*ch1 (r5) is a SEPARATE +0xC byproduct")
print("  (+24V rail / power-fail), NOT folded into PP (Agent I's '32*ch1+16*ch2' summary was wrong).")
print("  NAMING: 0x08088864 = AD_BAT (not 'CP analog'). D_LINK=PB12, PD11=GPIOD bit11 (BCB output")
print("  read-back). Replicated INERT in src/cp_adc.c (shares TIM8 with adc.c; measurement only,")
print("  NO power GPIO; BCB PD11 drive + power-fail queue stay GATED). host test_cp_adc 42 checks.")

print(f"\n{checks} checks, {failures} failures")
import sys
sys.exit(1 if failures else 0)