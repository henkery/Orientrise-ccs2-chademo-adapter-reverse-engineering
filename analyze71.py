#!/usr/bin/env python3
"""analyze71.py — correct-base peripheral map + MCU sub-family + RTOS reconnaissance.

Uses the ground-truth link base (REPORT §5.16): firmware.bin[F] runs at 0x0801FBFE+F
(verbatim install of fw[0x402:] proven for sector 5 by acq/dump/app5.bin; the boot copies
the whole image with the same transform). This HAL-style app stores peripheral bases in
rodata HANDLE TABLES (loaded via pointer chains), so peripheral references are found two ways:
  (1) raw stored-word scan — every u32 in the image matching a peripheral base/register;
  (2) code-loaded constants — movw/movt pairs + LDR-literal pools (corrected Thumb encodings).
Both are classified against the STM32F4 peripheral map to surface:
  * which peripherals the app touches (GPIOA..K, CAN1/2, SPI1..5, TIMn, USARTn, ADC, RCC,
    FLASH, PWR, SYSCFG/EXTI, USB, DMA, I2C, DAC, CRC) -> pin-map / CAN-assignment basis (§8.4/5);
  * F429/F439-only blocks (LTDC/DMA2D/FMC/SAI1) vs F437/F439-only crypto (CRYP/HASH) vs ETH
    -> narrows the exact sub-family (§8.1);
  * DBGMCU_IDCODE 0xE0042000 / flash-size 0x1FFF7A22 / UID 0x1FFF7A10 reads;
  * RTOS-identifying strings + the task-stat dump header + all *_process/*_task names (§8.7).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze71.py firmware.bin'
"""
import sys, struct, re, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TRUE_BASE = 0x0801FBFE          # firmware.bin[F] -> TRUE_BASE+F  (§5.16)
fw = open(sys.argv[1] if len(sys.argv) > 1 else 'firmware.bin', 'rb').read()
N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True

def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TRUE_BASE + f

PERIPH = [
    (0x40000000,'TIM2',0x400),(0x40000400,'TIM3',0x400),(0x40000800,'TIM4',0x400),
    (0x40000C00,'TIM5',0x400),(0x40001000,'TIM6',0x400),(0x40001400,'TIM7',0x400),
    (0x40001800,'TIM12',0x400),(0x40001C00,'TIM13',0x400),(0x40002000,'TIM14',0x400),
    (0x40003800,'SPI2',0x400),(0x40003C00,'SPI3',0x400),
    (0x40004400,'USART2',0x400),(0x40004800,'USART3',0x400),(0x40004C00,'UART4',0x400),
    (0x40005000,'UART5',0x400),(0x40005400,'I2C1',0x400),(0x40005800,'I2C2',0x400),
    (0x40005C00,'I2C3',0x400),(0x40006400,'CAN1',0x400),(0x40006800,'CAN2',0x400),
    (0x40007000,'PWR',0x400),(0x40007400,'DAC',0x400),(0x40007800,'UART7',0x400),
    (0x40007C00,'UART8',0x400),
    (0x40010000,'TIM1',0x400),(0x40010400,'TIM8',0x400),
    (0x40011000,'USART1',0x400),(0x40011400,'USART6',0x400),
    (0x40012000,'ADC1',0x100),(0x40012100,'ADC2',0x100),(0x40012200,'ADC3',0x100),
    (0x40012300,'ADCcommon',0x100),
    (0x40013000,'SPI1',0x400),(0x40013400,'SPI4',0x400),(0x40013800,'SYSCFG',0x400),
    (0x40013C00,'EXTI',0x400),(0x40014000,'TIM9',0x400),(0x40014400,'TIM10',0x400),
    (0x40014800,'TIM11',0x400),(0x40015000,'SPI5',0x400),(0x40015800,'SAI1',0x400),
    (0x40016800,'LTDC',0x400),
    (0x40020000,'GPIOA',0x400),(0x40020400,'GPIOB',0x400),(0x40020800,'GPIOC',0x400),
    (0x40020C00,'GPIOD',0x400),(0x40021000,'GPIOE',0x400),(0x40021400,'GPIOF',0x400),
    (0x40021800,'GPIOG',0x400),(0x40021C00,'GPIOH',0x400),(0x40022000,'GPIOI',0x400),
    (0x40022400,'GPIOJ',0x400),(0x40022800,'GPIOK',0x400),
    (0x40023000,'CRC',0x400),(0x40023700,'DMA1',0x400),(0x40023800,'RCC',0x400),
    (0x40023C00,'FLASH',0x400),(0x40026400,'DMA2',0x400),(0x40028000,'ETH',0x1000),
    (0x4002B000,'DMA2D',0x400),
    (0x40040000,'USB_OTG_HS',0x1000),(0x50000000,'USB_OTG_FS',0x1000),
    (0x50060000,'CRYP',0x400),(0x50060400,'HASH',0x400),(0x50060800,'RNG',0x400),
    (0xA0000000,'FMC_SDRAM',0x1000),(0x60000000,'FSMC/FMC_NOR',0x1000),
    (0xE000E010,'SysTick',0x100),(0xE000E100,'NVIC',0x800),(0xE000ED00,'SCB',0x100),
    (0xE0001000,'DWT',0x1000),(0xE0002000,'FPB',0x1000),(0xE0042000,'DBGMCU',0x100),
]
EXACT = {0x1FFF7A10:'UID(96bit)',0x1FFF7A22:'FLASH_SIZE_REG',0x1FFF7A20:'FLASH_SIZE_REG_lo',
         0xE0042000:'DBGMCU_IDCODE'}
def classify(v):
    if v in EXACT: return EXACT[v]
    for base,name,span in PERIPH:
        if base <= v < base+span: return name
    return None
def is_periph_range(v):
    return (0x40000000<=v<0x60000000) or (0xE0000000<=v<0xE0100000) \
        or (0xA0000000<=v<0xA0010000) or (0x1FFF7A00<=v<0x1FFF7A30)

# name -> value -> [(file_off, kind)]
sites = collections.defaultdict(lambda: collections.defaultdict(list))

# (1) raw stored-word scan (rodata handle tables)
nraw = 0
for o in range(0, N-3, 2):
    v = u32(o)
    if is_periph_range(v):
        c = classify(v)
        if c: sites[c][v].append((o, 'stored')); nraw += 1

# (2) code-loaded constants: movw/movt pairs + LDR-literal pools
movw_pending = {}; ncode = 0
for o in range(0, N-4, 2):
    h1 = u16(o); v = None; kind = None
    if (h1 & 0xFBF0) in (0xF240, 0xF2C0):           # movw / movt T3
        ins = list(md.disasm(fw[o:o+4], rt(o), count=1))
        if ins and ins[0].mnemonic in ('movw','movt') and len(ins[0].operands) == 2:
            i = ins[0]; reg = i.operands[0].reg; imm = i.operands[1].imm & 0xFFFF
            if i.mnemonic == 'movw': movw_pending[reg] = (imm, o)
            elif reg in movw_pending:
                lo, fo = movw_pending.pop(reg); v = (imm << 16) | lo; kind = 'movw/movt'; o = fo
    elif (h1 & 0xF800) == 0x4800:                    # LDR literal T1
        pca = ((rt(o)+4)&~3) - TRUE_BASE             # runtime-aligned PC+4 (base≡2 mod4, §5.16)
        t = pca + (h1&0xFF)*4
        if t+4 <= N: v = u32(t); kind = f'ldrT1@{t:05x}'
    elif (h1 & 0xFF7F) == 0xF85F:                    # LDR literal T2 (U=bit7)
        h2 = u16(o+2); u = (h1>>7)&1
        pca = ((rt(o)+4)&~3) - TRUE_BASE
        t = pca + ((h2&0xFFF) if u else -(h2&0xFFF))
        if 0 <= t and t+4 <= N: v = u32(t); kind = f'ldrT2@{t:05x}'
    if v is not None and is_periph_range(v):
        c = classify(v)
        if c: sites[c][v].append((o, kind)); ncode += 1

print(f"firmware.bin = {N} (0x{N:x}) B; true base 0x{TRUE_BASE:08X} (fw[F]->0x{TRUE_BASE:08X}+F)")
print(f"peripheral refs: {nraw} stored-word + {ncode} code-loaded")

print("\n== peripheral / system references (grouped; stored=rodata handle table) ==")
order = [n for _,n,_ in PERIPH] + list(EXACT.values())
seen = set()
def show(name):
    vals = sites[name]; nrefs = sum(len(s) for s in vals.values())
    stored = sum(1 for s in vals.values() for _,k in s if k=='stored')
    regs = ', '.join(f'0x{v:08X}' for v in sorted(vals)[:6])
    print(f"  {name:14s}: {nrefs:4d} refs ({stored} stored), {len(vals):3d} addrs  [{regs}{' …' if len(vals)>6 else ''}]")
for name in order:
    if name in sites and name not in seen: seen.add(name); show(name)
for name in sorted(sites):
    if name not in seen: show(name)

print("\n== MCU sub-family discriminators (§8.1) ==")
for key,note in [('LTDC','F429/F439 only'),('DMA2D','F429/F439 only'),('SAI1','F429/F439 only'),
                 ('FMC_SDRAM','F429/F439 only'),('CRYP','F437/F439 only'),('HASH','F437/F439 only'),
                 ('ETH','F427/429/437/439'),('RNG',''),('FSMC/FMC_NOR','F427/429/437/439')]:
    print(f"  {key:14s}: {'PRESENT' if key in sites else 'absent':8s}  {note}")
for key in ('DBGMCU_IDCODE','DBGMCU','FLASH_SIZE_REG','FLASH_SIZE_REG_lo','UID(96bit)'):
    if key in sites:
        for v in sorted(sites[key]):
            locs = ', '.join(f'f+0x{fo:05x}(0x{rt(fo):08X},{k})' for fo,k in sites[key][v][:6])
            print(f"  {key}: 0x{v:08X} @ {locs}")

print("\n== CAN1 / CAN2 reference sites (assignment, §8.5) ==")
for key in ('CAN1','CAN2'):
    for v in sorted(sites.get(key,{})):
        for fo,k in sites[key][v]:
            print(f"  {key} 0x{v:08X} @ f+0x{fo:05x} (0x{rt(fo):08X}) [{k}]")

print("\n== TIM2 register sites (prescaler/period for tick, §8.5) ==")
TIMREG = {0x00:'CR1',0x04:'CR2',0x08:'SMCR',0x0C:'DIER',0x10:'SR',0x14:'EGR',0x18:'CCMR1',
          0x1C:'CCMR2',0x20:'CCER',0x24:'CNT',0x28:'PSC',0x2C:'ARR',0x34:'CCR1',0x38:'CCR2',
          0x3C:'CCR3',0x40:'CCR4',0x48:'DCR',0x4C:'DMAR'}
for v in sorted(sites.get('TIM2',{})):
    off = v - 0x40000000; rn = TIMREG.get(off, f'+0x{off:02x}')
    locs = ', '.join(f'f+0x{fo:05x}({k})' for fo,k in sites['TIM2'][v][:6])
    print(f"  TIM2_{rn:6s} (0x{v:08X}): {len(sites['TIM2'][v])} refs [{locs}]")

print("\n== RTOS-identifying strings (§8.7) ==")
pats = [b'FreeRTOS',b'RT-Thread',b'rt_thread',b'rtthread',b'uC/OS',b'UCOS',b'uCOS',b'ThreadX',
        b'tx_thread',b'tx_queue',b'RTX',b'osThread',b'osKernel',b'osMutex',b'CMSIS',b'LiteOS',
        b'Liteos',b'Huawei',b'TencentOS',b'AliOS',b'RTT',b'vTask',b'xTask',b'OSTask',b'OS_TASK',
        b'PendSV',b'pendsv',b'SVC_Handler',b'SysTick_Handler',b'configUSE',b'portmacro',
        b'stack overflow',b'StackOverflow',b'IDLE',b'Task RT BASE',b'RT BASE IER',b'STKF',
        b'tskIDLE',b'pxPort',b'xPort',b'osRtx',b'rt_hw',b'rt_kprintf',b'finsh',b'msh',b'RT_NAME',b'rt_object']
for p in pats:
    idx = fw.find(p); hits = []
    while idx >= 0 and len(hits) < 4: hits.append(idx); idx = fw.find(p, idx+1)
    if hits:
        ctx = fw[hits[0]:hits[0]+48].split(b'\x00')[0]
        print(f"  {p.decode():16s}: {len(hits)} hit(s) first f+0x{hits[0]:05x} (0x{rt(hits[0]):08X}) ctx={ctx!r}")

print("\n== task / process name strings ==")
names = collections.OrderedDict()
for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{2,30}_(?:process|PROCESS|task|TASK|Task)', fw):
    names.setdefault(m.group().decode(), m.start())
for s, fo in names.items():
    print(f"  {s:28s} f+0x{fo:05x} (0x{rt(fo):08X})")
print(f"  {len(names)} distinct task/process names")

print("\n== task-stat dump header context ==")
for hdr in (b'Task RT BASE', b'RT BASE IER', b'STKF STKS', b'STKS ADDR'):
    idx = fw.find(hdr)
    if idx >= 0:
        chunks = fw[max(0,idx-16):idx+72].split(b'\x00')
        printable = [x for x in chunks if x and all(32<=c<127 for c in x)]
        print(f"  {hdr.decode()!r} @ f+0x{idx:05x} (0x{rt(idx):08X}): {printable}")