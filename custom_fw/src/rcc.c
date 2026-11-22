/* rcc.c — restore SYSCLK 168 MHz (HSE 8 MHz -> PLL) after the boot's clock deinit.
 * Register values byte-derived from the stock clock-config function (REPORT §5.8.1):
 *   PLLCFGR = 0x07402A04  (PLLM=4, PLLN=168, PLLP=2, PLLQ=7, PLLSRC=HSE)
 *   CFGR    prescalers: HPRE=/1, PPRE1=/4 (APB1=42 MHz), PPRE2=/2 (APB2=84 MHz), SW=PLL
 *   FLASH_ACR = 0x705     (5 wait-states + instruction/data cache + prefetch, 168 MHz @ 3.3 V)
 * The stock CFGR write 0x80209400 also routes MCO outputs; we omit MCO (not needed) and
 * set SW=PLL explicitly. PWR voltage scale 1 is required for 168 MHz on F427/429.
 */
#include "rcc.h"

#define RCC_BASE     0x40023800u
#define RCC_CR       (*(volatile uint32_t *)(RCC_BASE + 0x00u))
#define RCC_PLLCFGR  (*(volatile uint32_t *)(RCC_BASE + 0x04u))
#define RCC_CFGR     (*(volatile uint32_t *)(RCC_BASE + 0x08u))
#define RCC_AHB1ENR  (*(volatile uint32_t *)(RCC_BASE + 0x30u))
#define RCC_APB1ENR  (*(volatile uint32_t *)(RCC_BASE + 0x40u))
#define RCC_APB2ENR  (*(volatile uint32_t *)(RCC_BASE + 0x44u))
#define FLASH_ACR    (*(volatile uint32_t *)0x40023C00u)
#define PWR_CR       (*(volatile uint32_t *)0x40007000u)

#define RCC_CR_HSION   (1u << 0)
#define RCC_CR_HSIRDY  (1u << 1)
#define RCC_CR_HSEON   (1u << 16)
#define RCC_CR_HSERDY  (1u << 17)
#define RCC_CR_PLLON   (1u << 24)
#define RCC_CR_PLLRDY  (1u << 25)
#define RCC_CFGR_SW_MASK  (3u << 0)
#define RCC_CFGR_SW_HSI   (0u << 0)
#define RCC_CFGR_SW_PLL   (2u << 0)
#define RCC_CFGR_SWS_HSI  (0u << 2)
#define RCC_CFGR_SWS_PLL  (2u << 2)
#define RCC_CFGR_SWS_MASK (3u << 2)
#define RCC_APB1ENR_PWREN (1u << 28)
#define PWR_CR_VOS        (1u << 14)   /* voltage scale 1 -> up to 168 MHz */

void rcc_init(void)
{
    /* Enable PWR clock and select voltage scale 1 (needed for 168 MHz). */
    RCC_APB1ENR |= RCC_APB1ENR_PWREN;
    (void)RCC_APB1ENR;
    PWR_CR |= PWR_CR_VOS;

    /* Ensure HSI is running (safe SYSCLK source while we reprogram the PLL). */
    RCC_CR |= RCC_CR_HSION;
    while (!(RCC_CR & RCC_CR_HSIRDY)) { }

    /* Start HSE (8 MHz crystal) and wait ready. */
    RCC_CR |= RCC_CR_HSEON;
    while (!(RCC_CR & RCC_CR_HSERDY)) { }

    /* The boot leaves the PLL running as SYSCLK (it does NOT deinit clocks before the jump).
     * PLLCFGR is write-protected while PLLON=1, so programming it directly is silently ignored
     * and SYSCLK would stay at the boot's PLL frequency (wrong APB2 -> garbled UART baud, wrong
     * PLLQ -> no 48 MHz USB clock -> CDC fails, wrong SysTick -> init stalls -> IWDG reset loop).
     * Switch SYSCLK to HSI, disable the PLL, wait it unlock, THEN reprogram. */
    RCC_CFGR = (RCC_CFGR & ~RCC_CFGR_SW_MASK) | RCC_CFGR_SW_HSI;
    while ((RCC_CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_HSI) { }
    RCC_CR &= ~RCC_CR_PLLON;
    while (RCC_CR & RCC_CR_PLLRDY) { }

    /* Flash latency for 168 MHz @ 3.3 V: 5 WS + I/D cache + prefetch. */
    FLASH_ACR = 0x705u;

    /* PLL: HSE/4 * 168 / 2 = 168 MHz (PLLQ=7 for 48 MHz USB/SDIO/RNG). */
    RCC_PLLCFGR = 0x07402A04u;
    RCC_CR |= RCC_CR_PLLON;
    while (!(RCC_CR & RCC_CR_PLLRDY)) { }

    /* AHB=/1, APB1=/4 (42 MHz), APB2=/2 (84 MHz); switch SYSCLK to PLL.
     * PPRE1=5 (/4) << 10, PPRE2=4 (/2) << 13, HPRE=0 (/1), SW=PLL(2). */
    RCC_CFGR = (5u << 10) | (4u << 13) | RCC_CFGR_SW_PLL;
    while ((RCC_CFGR & RCC_CFGR_SWS_MASK) != RCC_CFGR_SWS_PLL) { }
}