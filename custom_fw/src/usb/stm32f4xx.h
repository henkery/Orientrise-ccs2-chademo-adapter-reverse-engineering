/* stm32f4xx.h — MINIMAL freestanding CMSIS shim for the TinyUSB dwc2 STM32F4 port ONLY.
 *
 * custom_fw is bare-metal (no ST CMSIS pack). The vendored TinyUSB dwc2_stm32.h does
 * #include "stm32f4xx.h" and uses just these symbols; this shim provides exactly them, nothing more.
 * It is NOT a general CMSIS header — other custom_fw modules poke registers directly (their own
 * #defines) and do not include this.
 *
 *   USB_OTG_FS_PERIPH_BASE   OTG_FS register base (DesignWare dwc2)
 *   USB_OTG_FS_MAX_IN_ENDPOINTS  FS IN endpoint count (incl EP0)
 *   OTG_FS_IRQn              OTG_FS global interrupt number (F427/F429 = 67)
 *   IRQn_Type / NVIC_EnableIRQ / NVIC_DisableIRQ  interrupt enable/disable
 *   SystemCoreClock          core clock (Hz) for the dwc2 remote-wakeup delay (defined in usb_hw.c)
 *   __NOP                    no-op
 *
 * The dwc2_phy_init RCC_AHB1LPENR_* branches are #if defined-guarded and are NOT defined here, so they
 * compile out (F4 FS PHY only needs stm32_gccfg PWRDWN, handled by the driver via dwc2_type.h).
 */
#ifndef STM32F4XX_SHIM_H
#define STM32F4XX_SHIM_H
#include <stdint.h>

#define USB_OTG_FS_PERIPH_BASE        0x50000000UL
#define USB_OTG_FS_MAX_IN_ENDPOINTS   4u
#define OTG_FS_IRQn                   67

typedef int IRQn_Type;

#define NVIC_ISER ((volatile uint32_t *)0xE000E100UL)
#define NVIC_ICER ((volatile uint32_t *)0xE000E180UL)

static inline void NVIC_EnableIRQ(IRQn_Type irqn)
{
    NVIC_ISER[(uint32_t)irqn >> 5] = (1UL << ((uint32_t)irqn & 0x1Fu));
}
static inline void NVIC_DisableIRQ(IRQn_Type irqn)
{
    NVIC_ICER[(uint32_t)irqn >> 5] = (1UL << ((uint32_t)irqn & 0x1Fu));
}

static inline void __NOP(void) { __asm volatile ("nop"); }

extern uint32_t SystemCoreClock;   /* defined in usb_hw.c (= 168 MHz) */

#endif /* STM32F4XX_SHIM_H */