@ startup.s — self-bootstrapping Cortex-M4 startup for the custom adapter app.
@ The stock bootloader branches to the app reset vector (word @0x08020004) with interrupts
@ disabled and clocks deinitialised; it writes NO MSP/VTOR (REPORT §5.15/§5.16). So this
@ Reset_Handler sets MSP from its own vector[0], relocates VTOR to the app base, copies
@ .data, zeroes .bss + CCM, then calls main. Mirrors the stock startup @0x08020008 (§5.16).

  .syntax unified
  .cpu cortex-m4
  .thumb

@ ---------------------------------------------------------------------------
@ Vector table — placed first in FLASH at 0x08020000 (.isr_vector).
@ Only the 16 core exceptions are populated; no external IRQ is enabled by the
@ inert skeleton, so peripheral vectors are left at the default handler.
@ ---------------------------------------------------------------------------
  .section .isr_vector, "a", %progbits
  .global _vectors
  .type _vectors, %object
_vectors:
  .word _estack            @ 0  initial MSP (0x20030000)
  .word Reset_Handler      @ 1  reset
  .word Default_Handler    @ 2  NMI
  .word Default_Handler    @ 3  HardFault
  .word Default_Handler    @ 4  MemManage
  .word Default_Handler    @ 5  BusFault
  .word Default_Handler    @ 6  UsageFault
  .word 0                  @ 7  reserved
  .word 0                  @ 8  reserved
  .word 0                  @ 9  reserved
  .word 0                  @ 10 reserved
  .word Default_Handler    @ 11 SVCall
  .word Default_Handler    @ 12 DebugMonitor
  .word 0                  @ 13 reserved
  .word Default_Handler    @ 14 PendSV
  .word Default_Handler    @ 15 SysTick
  .size _vectors, . - _vectors

@ ---------------------------------------------------------------------------
  .text
  .thumb_func
  .global Reset_Handler
  .type Reset_Handler, %function
Reset_Handler:
  @ MSP <- vector[0] (_estack). Done first, before any stack use.
  ldr   r0, =_estack
  msr   msp, r0

  @ SCB->VTOR (0xE000ED08) <- app base 0x08020000
  ldr   r0, =0x08020000
  ldr   r1, =0xE000ED08
  str   r0, [r1]

  @ copy .data from FLASH (LMA _sidata) to RAM (_sdata.._edata)
  ldr   r0, =_sidata
  ldr   r1, =_sdata
  ldr   r2, =_edata
.Lcopy:
  cmp   r1, r2
  bcs   .Lzero_bss
  ldr   r3, [r0], #4
  str   r3, [r1], #4
  b     .Lcopy

.Lzero_bss:
  @ zero .bss (_sbss.._ebss)
  ldr   r1, =_sbss
  ldr   r2, =_ebss
  movs  r3, #0
.Lzb:
  cmp   r1, r2
  bcs   .Lzero_ccm
  str   r3, [r1], #4
  b     .Lzb

.Lzero_ccm:
  @ zero CCM (.ccm_bss _sccm.._eccm)
  ldr   r1, =_sccm
  ldr   r2, =_eccm
.Lzc:
  cmp   r1, r2
  bcs   .Lcall_main
  str   r3, [r1], #4
  b     .Lzc

.Lcall_main:
  bl    main
  b     .                  @ main should never return; trap if it does
  .size Reset_Handler, . - Reset_Handler

  .thumb_func
  .global Default_Handler
  .type Default_Handler, %function
Default_Handler:
  b     .                  @ unused exception: hang safely (no power-stage action)
  .size Default_Handler, . - Default_Handler

  .end