@ startup.s — self-bootstrapping Cortex-M4 startup for the custom adapter app.
@ The stock bootloader branches to the app reset vector (word @0x08020004) with interrupts
@ disabled and clocks deinitialised; it writes NO MSP/VTOR (REPORT §5.15/§5.16). So this
@ Reset_Handler sets MSP from its own vector[0], relocates VTOR to the app base, copies
@ .data, zeroes .bss + CCM, then calls main. Mirrors the stock startup @0x08020008 (§5.16).
@
@ Exception handlers are WEAK aliases to Default_Handler so C ISRs (e.g. SysTick_Handler in
@ tick.c, CAN1_RX0_IRQHandler later) override them by defining the strong symbol.

  .syntax unified
  .cpu cortex-m4
  .thumb

@ ---------------------------------------------------------------------------
@ Vector table — first in FLASH at 0x08020000 (.isr_vector). 16 core exceptions
@ + 91 external IRQs (STM32F427/429). External IRQs default to Default_Handler
@ until a strong C handler overrides the named weak symbol.
@ ---------------------------------------------------------------------------
  .section .isr_vector, "a", %progbits
  .global _vectors
  .type _vectors, %object
_vectors:
  .word _estack            @ 0  initial MSP (0x20030000)
  .word Reset_Handler      @ 1  reset
  .word NMI_Handler        @ 2  NMI
  .word HardFault_Handler  @ 3  HardFault
  .word MemManage_Handler  @ 4  MemManage
  .word BusFault_Handler   @ 5  BusFault
  .word UsageFault_Handler @ 6  UsageFault
  .word 0                  @ 7  reserved
  .word 0                  @ 8  reserved
  .word 0                  @ 9  reserved
  .word 0                  @ 10 reserved
  .word SVC_Handler        @ 11 SVCall
  .word DebugMon_Handler   @ 12 DebugMonitor
  .word 0                  @ 13 reserved
  .word PendSV_Handler     @ 14 PendSV
  .word SysTick_Handler    @ 15 SysTick
  @ external IRQs 0..90 (vector position = 16 + IRQn). CAN1_TX=19, RX0=20, RX1=21, SCE=22.
  .rept 19                     @ IRQ0..18
  .word Default_Handler
  .endr
  .word CAN1_TX_IRQHandler     @ IRQ19
  .word CAN1_RX0_IRQHandler    @ IRQ20
  .word CAN1_RX1_IRQHandler    @ IRQ21
  .word CAN1_SCE_IRQHandler    @ IRQ22
  .rept 7                      @ IRQ23..29
  .word Default_Handler
  .endr
  .word TIM4_IRQHandler        @ IRQ30 (CP PWM input capture, cp_capture.c)
  .rept 6                      @ IRQ31..36
  .word Default_Handler
  .endr
  .word USART1_IRQHandler      @ IRQ37 (uart_dbg RX reset-command ring buffer)
  .rept 18                     @ IRQ38..55
  .word Default_Handler
  .endr
  .word DMA2_Stream0_IRQHandler @ IRQ56 (HV ADC DMA accumulation, adc.c)
  .word DMA2_Stream1_IRQHandler @ IRQ57 (CP/PP ADC3 DMA accumulation, cp_adc.c)
  .rept 9                      @ IRQ58..66
  .word Default_Handler
  .endr
  .word OTG_FS_IRQHandler      @ IRQ67 (USB device CDC revert console, usb_hw.c)
  .rept 23                     @ IRQ68..90
  .word Default_Handler
  .endr
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
  ldr   r1, =_sbss
  ldr   r2, =_ebss
  movs  r3, #0
.Lzb:
  cmp   r1, r2
  bcs   .Lzero_ccm
  str   r3, [r1], #4
  b     .Lzb

.Lzero_ccm:
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

@ weak aliases: a strong C definition of any of these overrides Default_Handler.
  .weak NMI_Handler
  .thumb_set NMI_Handler, Default_Handler
  .weak HardFault_Handler
  .thumb_set HardFault_Handler, Default_Handler
  .weak MemManage_Handler
  .thumb_set MemManage_Handler, Default_Handler
  .weak BusFault_Handler
  .thumb_set BusFault_Handler, Default_Handler
  .weak UsageFault_Handler
  .thumb_set UsageFault_Handler, Default_Handler
  .weak SVC_Handler
  .thumb_set SVC_Handler, Default_Handler
  .weak DebugMon_Handler
  .thumb_set DebugMon_Handler, Default_Handler
  .weak PendSV_Handler
  .thumb_set PendSV_Handler, Default_Handler
  .weak SysTick_Handler
  .thumb_set SysTick_Handler, Default_Handler
  .weak CAN1_TX_IRQHandler
  .thumb_set CAN1_TX_IRQHandler, Default_Handler
  .weak CAN1_RX0_IRQHandler
  .thumb_set CAN1_RX0_IRQHandler, Default_Handler
  .weak CAN1_RX1_IRQHandler
  .thumb_set CAN1_RX1_IRQHandler, Default_Handler
  .weak CAN1_SCE_IRQHandler
  .thumb_set CAN1_SCE_IRQHandler, Default_Handler
  .weak TIM4_IRQHandler
  .thumb_set TIM4_IRQHandler, Default_Handler
  .weak USART1_IRQHandler
  .thumb_set USART1_IRQHandler, Default_Handler
  .weak DMA2_Stream0_IRQHandler
  .thumb_set DMA2_Stream0_IRQHandler, Default_Handler
  .weak DMA2_Stream1_IRQHandler
  .thumb_set DMA2_Stream1_IRQHandler, Default_Handler
  .weak OTG_FS_IRQHandler
  .thumb_set OTG_FS_IRQHandler, Default_Handler

  .end