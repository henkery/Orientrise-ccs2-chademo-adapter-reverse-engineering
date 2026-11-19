/* rcc.h — clock configuration for the custom adapter app (STM32F427/F429).
 * The stock bootloader deinitialises the clocks before jumping to the app (REPORT §5.15:
 * RCC AHB2/3/APB1/2 = 0), so the app must restore SYSCLK itself. Values byte-derived from
 * the stock clock-config function (REPORT §5.8.1, analyze79): HSE 8 MHz, PLLM=4 PLLN=168
 * PLLP=2 PLLQ=7 -> 168 MHz; APB1=/4 (42 MHz), APB2=/2 (84 MHz); timer clocks x2 on APB1.
 */
#ifndef RCC_H
#define RCC_H
#include <stdint.h>

#define SYSCLK_HZ    168000000u
#define AHB_HZ       168000000u
#define APB1_HZ      42000000u
#define APB2_HZ      84000000u
#define APB1_TIM_HZ  84000000u   /* x2 because PPRE1 > 1 */
#define APB2_TIM_HZ  168000000u  /* x2 because PPRE2 > 1 */

void rcc_init(void);

#endif /* RCC_H */