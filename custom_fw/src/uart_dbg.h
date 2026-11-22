/* uart_dbg.h — temporary bench init-progress trace on USART1 (PA9 TX, 230400 8N1).
 * Diagnostic only: prints a marker after each init step + a periodic loop heartbeat so the
 * boot UART bridge can show how far the app gets before a stall. Remove once CDC is verified. */
#ifndef UART_DBG_H
#define UART_DBG_H
#include <stdint.h>
void uart_dbg_init_early(void);   /* USART1 @ reset-default HSI 16 MHz (before rcc_init) */
void uart_dbg_init(void);         /* USART1 @ 84 MHz APB2 (after rcc_init) */
void uart_dbg_puts(const char *s);
void uart_dbg_hex32(uint32_t v);
void uart_dbg_poll_reset(void);   /* TEMP bench: RX "RST" command -> system reset into boot (hands-free reflash) */
#endif /* UART_DBG_H */