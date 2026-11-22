/* usb_hw.c — STM32F4 OTG_FS device bring-up for the TinyUSB CDC revert console (REPORT §5.15c).
 *
 * The boot has no USB (§5.15b); this is an APP-side device-mode console. The USB port also charges the
 * internal battery (device/sink VBUS role) so device mode is hardware-feasible. rcc.c already sets
 * PLLQ=7 -> 48 MHz USB clock. Here we enable the OTG_FS peripheral clock (RCC_AHB2ENR.OTGFSEN) + the
 * PA11/PA12 (OTG_FS_DM/DP) AF10 pins, then tud_init(0). No VBUS-sense pin (PA9/PA10 = USART1): the dwc2
 * driver forces B-valid + NOVBUSSENS (CFG_TUD_VBUS_DETECT_HW=0). The OTG_FS global IRQ (67) is enabled
 * by the stack (dwc2_int_set -> NVIC_EnableIRQ) and serviced here via tud_int_handler.
 */
#include "usb_hw.h"
#include "tusb.h"

#define RCC_AHB1ENR (*(volatile uint32_t *)0x40023830u)
#define RCC_AHB2ENR (*(volatile uint32_t *)0x40023838u)
#define GPIOA_BASE  0x40020000u
#define REG(b, o)   (*(volatile uint32_t *)((b) + (o)))
#define GPIOA_MODER   REG(GPIOA_BASE, 0x00u)
#define GPIOA_OSPEEDR REG(GPIOA_BASE, 0x08u)
#define GPIOA_AFRH    REG(GPIOA_BASE, 0x24u)

/* Core clock for the dwc2 remote-wakeup delay (rcc.c: HSE 8 MHz, PLLN=168 PLLM=4 PLLP=2 -> 168 MHz). */
uint32_t SystemCoreClock = 168000000u;

void usb_hw_init(void)
{
    RCC_AHB1ENR |= (1u << 0);             /* GPIOA */
    RCC_AHB2ENR |= (1u << 7);             /* OTG_FS (OTGFSEN) */
    (void)RCC_AHB1ENR; (void)RCC_AHB2ENR;

    /* PA11 = OTG_FS_DM, PA12 = OTG_FS_DP: AF10, high speed. */
    GPIOA_OSPEEDR |= (3u << 22) | (3u << 24);
    GPIOA_MODER = (GPIOA_MODER & ~((3u << 22) | (3u << 24)))
                | (2u << 22) | (2u << 24);
    GPIOA_AFRH = (GPIOA_AFRH & ~((0xFu << 12) | (0xFu << 16)))
               | (0xAu << 12) | (0xAu << 16);

    tud_init(0);                          /* TinyUSB device stack on RHPort0 (OTG_FS) */
}

/* OTG_FS global interrupt (IRQ 67) -> TinyUSB device ISR. */
void OTG_FS_IRQHandler(void)
{
    tud_int_handler(0);
}