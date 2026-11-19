#!/usr/bin/env python3
"""analyze83.py — memory/linker layout + custom-firmware build/flash/recovery recipe (§5.19, roadmap F):
consolidates the bricking-critical layout facts into an actionable recipe for building a custom app that
the stock bootloader will launch and that can be flashed back to stock. Re-derives the layout from the
C009 firmware.bin bytes (the layout is hardware-invariant; C013 only shifts code):

Parts:
  1. Decode the flash-writer's two 12-entry sector tables (sizes @file 0x9119E, start-offsets @0x911CE)
     -> the exact 1 MB / 12-sector flash map (boot 0-4, app 5-9, logs 10-11).
  2. Decode the ARM scatterload region table (adr@0x45E -> sl/fp pointers -> 4 x {load,exec,size,fn})
     -> .data/.bss/CCM regions, .bss end, free-SRAM scratch gap, MSP stack top.
  3. Emit a GNU ld linker script (MEMORY + SECTIONS) for a custom app linked at 0x08020000 (sector 5),
     grounded in the decoded flash/RAM layout.
  4. Print the UPG packaging + install + stock-recovery recipe (the transform make_service_upg.py
     implements; §5.12/§5.13/§5.16): self-described XOR key, 0x402 header strip, verbatim install,
     CRC16/MODBUS re-seal, boot-survives recovery.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze83.py'
"""
import struct

TB = 0x0801FBFE
fw = open('firmware.bin', 'rb').read(); N = len(fw)
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f

print("== 1. flash sector map (from the flash-writer's own tables) ==")
sizes  = [u32(0x9119E + k*4) for k in range(12)]   # sector size table
starts = [u32(0x911CE + k*4) for k in range(12)]   # sector start-offset table (cumulative)
FLASH_BASE = 0x08000000
def role(k):
    if k <= 4:  return 'bootloader (BOOT_…UPG; recovery anchor)'
    if k <= 9:  return 'main app (MAIN_…UPG; this image)'
    return 'logs / config (EVCC…LOGS)'
for k in range(12):
    a = FLASH_BASE + starts[k]
    print(f"  sector {k:2d}: 0x{a:08X}..0x{a+sizes[k]-1:08X}  {sizes[k]//1024:3d} KB  {role(k)}")
app_start = FLASH_BASE + starts[5]
app_end   = FLASH_BASE + starts[9] + sizes[9]
print(f"  => app region 0x{app_start:08X}..0x{app_end:08X} ({(app_end-app_start)//1024} KB, sectors 5-9)")

print("\n== 2. scatterload region table -> RAM layout ==")
r0 = rt(0x48A)                       # adr@0x45E target
sl = r0 + u32(0x48A); fp = r0 + u32(0x48E)
FN = {0x080200EC:'copy', 0x08020090:'decompress', 0x08020108:'zero'}
bss_end = None; ccm_size = None
a = sl - TB
while a < fp - TB:
    load, exec_, size, fn = u32(a), u32(a+4), u32(a+8), u32(a+12)
    kind = FN.get(fn, f'fn0x{fn:08X}')
    region = 'CCM' if exec_ >= 0x10000000 and exec_ < 0x10010000 else 'SRAM'
    print(f"  {region:4s} {kind:10s} load 0x{load:08X} -> exec 0x{exec_:08X}, size 0x{size:X} ({size})")
    if region == 'SRAM' and kind == 'zero': bss_end = exec_ + size
    if region == 'CCM': ccm_size = size
    a += 16
SRAM_BASE = 0x20000000; SRAM_SIZE = 0x30000; STACK_TOP = SRAM_BASE + SRAM_SIZE
print(f"  main SRAM 0x{SRAM_BASE:08X}..0x{STACK_TOP-1:08X} (192 KB); CCM 0x10000000 (64 KB)")
print(f"  .bss end = 0x{bss_end:08X} (= stock vector SP); MSP stack top = 0x{STACK_TOP:08X}")
print(f"  free SRAM scratch gap 0x{bss_end:08X}..0x{STACK_TOP:08X} = {STACK_TOP-bss_end} B (cave/scratch)")

print("\n== 3. GNU ld linker script for a custom app at 0x08020000 (sector 5) ==")
ld = f"""/* Custom Orientrise-clone app — linked for the stock bootloader's verbatim install.
 * Boot strips the 0x402-byte UPG header and copies fw[0x402:] to 0x08020000 (sector 5).
 * The app self-bootstraps: Reset_Handler sets MSP from vector[0], VTOR=0x08020000,
 * zeroes .bss/.ccm_bss, copies .data, then calls main. No boot-patched literals. */
MEMORY {{
  FLASH (rx)  : ORIGIN = 0x08020000, LENGTH = 640K   /* sectors 5-9 */
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 192K   /* main SRAM */
  CCM   (rwx) : ORIGIN = 0x10000000, LENGTH = 64K    /* CCM RAM */
}}
_estack = ORIGIN(RAM) + LENGTH(RAM);   /* 0x20030000 — MSP top */
SECTIONS {{
  .isr_vector : {{ KEEP(*(.isr_vector)) }} > FLASH   /* vector[0]=SP, [1]=Reset_Handler */
  .text       : {{ *(.text*) *(.rodata*) }} > FLASH
  .data       : {{ *(.data*) }} > RAM AT> FLASH      /* scatterload copy */
  .bss        : {{ *(.bss*) *(COMMON) }} > RAM        /* zero-fill */
  .ccm_bss    : {{ *(.ccm_bss*) }} > CCM              /* zero-fill */
  ._sidata = LOADADDR(.data);
}}
"""
print(ld)

print("== 4. UPG packaging + install + stock-recovery recipe ==")
print("""  BUILD a custom UPG (make_service_upg.py implements this transform):
   1. Outer XOR key is self-described: key0=raw[0], key1=raw[0]^raw[1] (C009=2B23, C013=25A8).
   2. Decoded layout: dec[0:2]=key echo; dec[2:0x58]=$$ version/date header;
      dec[0x58:0x400]=high-entropy prefix (DISCARDED by boot — keep stock);
      dec[0x400:0x402]=2 discarded bytes; dec[0x402:0x40A]=8-byte vector SP+reset;
      dec[0x40A:]=app code (Reset_Handler first).
   3. length u32LE @0x3F2 = filesize-0x404; footer CRC u16LE @0x3FE =
      CRC16/MODBUS(dec[0x3EA:0x3FE]); trailer dec[n-4:n] = 00 00 + CRC16/MODBUS(dec[2:n-2]).
      MODBUS = poly 0xA001 (reflected 0x8005), init 0xFFFF, refin/refout true, xorout 0.
   4. Re-XOR the whole image with the key; name it MAIN_CCS2CHADEMO_1.UPG; put on a FAT32
      USB stick root (label is NOT checked). The app's usbdisk process reads it, writes flash,
      resets; the BOOTLOADER then XOR-decodes + CRC-verifies + strips 0x402 + installs verbatim.
  INSTALL (boot side, §5.16 ground truth): copy fw[0x402:] verbatim to 0x08020000 — NO cipher,
   NO patch. App vectors SP=0x20024D18/reset=0x08020009 install as-is; Reset_Handler @0x08020008
   self-bootstraps (MSP/PSP from vector[0], zero SRAM+CCM, scatterload, __main). Boot-time check =
   CRC16/MODBUS residue + config-block additive checksum/magic 0x55AA55AA; NO whole-image hash.
  RECOVER to stock (bricking-safe):
   - Bootloader (sectors 0-4) is NEVER touched by a MAIN update => it survives a failed app flash.
   - SERVICE.UPG = byte-identical stock round-trip (make_service_upg.py STOCK -o SERVICE.UPG):
     re-flash it to restore the exact stock app. Bench-confirmed dump caves also exist (§5.13f/i).
   - Boot has its own USB update path + XMODEM-1K serial recovery; SWD read is non-destructive at
     RDP0 (NEVER RDP-unlock — that mass-erases). acq/ kit = ESP32-S3 CMSIS-DAP + OpenOCD fallback.""")

print("\n== RESOLVED build/flash/recovery basis (roadmap F) ==")
print("  Flash: boot 0-4 (128K) / app 5-9 (640K, link 0x08020000) / logs 10-11 (256K).")
print("  RAM: 192K SRAM @0x20000000 (stack top 0x20030000) + 64K CCM @0x10000000; .bss end 0x20024D18.")
print("  Custom app: link at 0x08020000, self-bootstrapping Reset_Handler, wrap via make_service_upg.py")
print("  (stock prefix/entry verbatim + re-sealed MODBUS CRCs); recover with SERVICE.UPG stock round-trip.")