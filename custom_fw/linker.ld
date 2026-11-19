/* linker.ld — custom app for the Orientrise KM-CCS2CHAdeMO-1 adapter (STM32F427/F429).
 * Layout byte-derived from the stock scatterload + flash-writer tables (REPORT §5.19, analyze83).
 * The stock bootloader installs fw[0x402:] VERBATIM at 0x08020000 and branches to the app reset
 * vector (word @0x08020004); it writes NO MSP/VTOR (§5.15/§5.16) — the app self-bootstraps.
 *
 *   FLASH : app sectors 5-9   0x08020000 .. 0x080BFFFF  (640 KB)
 *   RAM   : main SRAM         0x20000000 .. 0x2002FFFF  (192 KB), MSP stack top 0x20030000
 *   CCM   : core-coupled RAM  0x10000000 .. 0x1000FFFF  (64 KB)
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08020000, LENGTH = 640K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 192K
  CCM   (rwx) : ORIGIN = 0x10000000, LENGTH = 64K
}

_estack = ORIGIN(RAM) + LENGTH(RAM);   /* 0x20030000 — vector[0] initial MSP */

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector :
  {
    . = ALIGN(4);
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > FLASH

  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    *(.glue_7) *(.glue_7t)
    . = ALIGN(4);
    _etext = .;
  } > FLASH

  /* .data lives in RAM, loaded from FLASH (LMA). _sidata = flash load address. */
  _sidata = LOADADDR(.data);
  .data :
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data*)
    . = ALIGN(4);
    _edata = .;
  } > RAM AT> FLASH

  .bss (NOLOAD) :
  {
    . = ALIGN(4);
    _sbss = .;
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  .ccm_bss (NOLOAD) :
  {
    . = ALIGN(4);
    _sccm = .;
    *(.ccm_bss*)
    . = ALIGN(4);
    _eccm = .;
  } > CCM

  /DISCARD/ : { *(.comment) *(.ARM.attributes) *(.eh_frame*) }
}