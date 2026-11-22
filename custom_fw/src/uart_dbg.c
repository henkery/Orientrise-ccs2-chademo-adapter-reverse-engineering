/* uart_dbg.c — temporary bench init-progress trace on USART1 (PA9 TX, 230400 8N1).
 * Diagnostic only (see uart_dbg.h). USART1 is on APB2 (84 MHz after rcc_init). The boot uses
 * USART1 for recovery; once the app launches the peripheral is free for this trace. PA9 = TX
 * (AF7); RX not needed. Blocking TXE-paced writes — a marker is ~10 chars (~0.4 ms), negligible
 * against the 10 ms tick. Remove once CDC enumeration is verified. */
#include "uart_dbg.h"

#define RCC_AHB1ENR (*(volatile uint32_t *)0x40023830u)
#define RCC_APB2ENR (*(volatile uint32_t *)0x40023844u)
#define GPIOA_BASE  0x40020000u
#define GPIOA_MODER (*(volatile uint32_t *)(GPIOA_BASE + 0x00u))
#define GPIOA_AFRH  (*(volatile uint32_t *)(GPIOA_BASE + 0x24u))
#define USART1_BASE 0x40011000u
#define USART1_SR   (*(volatile uint32_t *)(USART1_BASE + 0x00u))
#define USART1_DR   (*(volatile uint32_t *)(USART1_BASE + 0x04u))
#define USART1_BRR  (*(volatile uint32_t *)(USART1_BASE + 0x08u))
#define USART1_CR1  (*(volatile uint32_t *)(USART1_BASE + 0x0Cu))
#define SR_TXE      (1u << 7)
#define SR_RXNE     (1u << 5)
#define CR1_UE      (1u << 13)
#define CR1_TE      (1u << 3)
#define CR1_RE      (1u << 2)
#define CR1_RXNEIE  (1u << 5)
#define SCB_AIRCR   (*(volatile uint32_t *)0xE000ED0Cu)
#define NVIC_ISER1  (*(volatile uint32_t *)0xE000E104u)   /* IRQ32..63 set-enable; USART1=37 -> bit5 */

/* RX ring buffer filled by the USART1 ISR at wire rate. The flash tool floods RX with 0x55 sync
 * (1280 B/s); polling RX from the 100 Hz main loop overruns the 1-byte DR and loses the "RST"
 * command. The ISR captures every byte here; uart_dbg_poll_reset drains it. 256 B ~= 200 ms of sync. */
#define RX_BUF_SIZE 256u
static volatile uint8_t  rx_buf[RX_BUF_SIZE];
static volatile uint16_t rx_head, rx_tail;

void USART1_IRQHandler(void)
{
    if (USART1_SR & SR_RXNE) {
        uint8_t b = (uint8_t)USART1_DR;          /* reading DR clears RXNE (and ORE) */
        uint16_t next = (uint16_t)((rx_head + 1u) % RX_BUF_SIZE);
        if (next != rx_tail) {                   /* drop on full (never block the ISR) */
            rx_buf[rx_head] = b;
            rx_head = next;
        }
    }
}

static void uart_setup(uint32_t brr)
{
    RCC_AHB1ENR |= (1u << 0);            /* GPIOA */
    RCC_APB2ENR |= (1u << 4);            /* USART1 */
    (void)RCC_AHB1ENR; (void)RCC_APB2ENR;
    /* PA9 = USART1_TX, AF7 (AFRH pin9 = bits[7:4]); MODER pin9 = bits[19:18] = 10 (AF). */
    GPIOA_MODER = (GPIOA_MODER & ~(3u << 18)) | (2u << 18);
    GPIOA_AFRH  = (GPIOA_AFRH & ~(0xFu << 4)) | (0x7u << 4);
    /* PA10 = USART1_RX, AF7 (AFRH pin10 = bits[11:8]); MODER pin10 = bits[21:20] = 10 (AF). */
    GPIOA_MODER = (GPIOA_MODER & ~(3u << 20)) | (2u << 20);
    GPIOA_AFRH  = (GPIOA_AFRH & ~(0xFu << 8)) | (0x7u << 8);
    USART1_BRR  = brr;
    USART1_CR1  = CR1_UE | CR1_TE | CR1_RE | CR1_RXNEIE;   /* 8N1, TX + RX IRQ (reset command intake) */
    NVIC_ISER1  = (1u << 5);             /* enable USART1 global IRQ (37) */
}

/* Before rcc_init: after a system reset RCC defaults to HSI 16 MHz, APB2 = 16 MHz.
 * BRR = 16 MHz / 230400 ~= 69 (0x45). Lets us print a marker even if rcc_init later hangs. */
void uart_dbg_init_early(void)
{
    uart_setup(0x45u);
}

/* After rcc_init: APB2 = 84 MHz. BRR = 84 MHz / 230400 ~= 365 (0x16D, 0.1% error). */
void uart_dbg_init(void)
{
    uart_setup(0x16Du);
}

static void putc(char c)
{
    while (!(USART1_SR & SR_TXE)) { }
    USART1_DR = (uint32_t)(uint8_t)c;
}

void uart_dbg_puts(const char *s)
{
    while (*s)
        putc(*s++);
}

void uart_dbg_hex32(uint32_t v)
{
    uart_dbg_puts("0x");
    for (int i = 28; i >= 0; i -= 4) {
        uint32_t n = (v >> i) & 0xFu;
        putc((char)(n < 10u ? ('0' + n) : ('A' + n - 10u)));
    }
}

/* TEMP bench: drain the RX ring buffer (filled by USART1_IRQHandler) for the reset command "RST"
 * and trigger a system reset into the boot. A 3-char state machine tolerates the 0x55 ('U') sync
 * bytes the flash tool streams between commands (any non-matching byte resets the match, 'R'
 * restarts it). On a full match, SYSRESETREQ resets the MCU; the boot then runs and catches the
 * continuing 0x55 sync -> XMODEM recovery. Hands-free reflash. Call from the main loop AND the
 * qca7005 idle hook so it works during modem bring-up too. */
void uart_dbg_poll_reset(void)
{
    static uint8_t st;
    while (rx_tail != rx_head) {
        uint8_t b = rx_buf[rx_tail];
        rx_tail = (uint16_t)((rx_tail + 1u) % RX_BUF_SIZE);
        if (b == (uint8_t)"RST"[st]) {
            if (++st == 3u) {
                uart_dbg_puts("RST->boot\r\n");
                SCB_AIRCR = 0x05FA0004u;   /* VECTKEY=0x05FA, SYSRESETREQ */
                for (;;) { }               /* wait for the reset to take effect */
            }
        } else {
            st = (b == (uint8_t)'R') ? 1u : 0u;
        }
    }
}