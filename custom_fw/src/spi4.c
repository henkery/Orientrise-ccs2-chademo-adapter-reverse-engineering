/* spi4.c — SPI4 external-flash read transport (REPORT §5.21 measurement addendum).
 *
 * Faithful replica of the stock SPI4 front-end used to read the factory NV calibration:
 *   - SPI4 init 0x08088C38: CR1 = 0x344 (CPOL=0/CPHA=0 mode 0, master, BR=/2 -> 42 MHz,
 *     8-bit, MSB-first, SSM+SSI, SPE), CR2 = 0. CS = PE11 (software, active-low).
 *   - NV read core 0x08088CFE: assert CS, send READ 0x03 + 24-bit address (MSB first),
 *     clock out `len` bytes with dummy 0x00 writes, deassert CS. 2 MB address space.
 * SCK=PE12 / MISO=PE13 / MOSI=PE14 (AF5). Read-only: no write/erase/status ops are needed
 * to read the calibration, so none are implemented (the external NV is never modified).
 */
#include "spi4.h"

#define RCC_AHB1ENR   (*(volatile uint32_t *)0x40023830u)
#define RCC_APB2ENR   (*(volatile uint32_t *)0x40023844u)
#define GPIOE_BASE    0x40021000u
#define SPI4_BASE     0x40013400u
#define REG(b, o)     (*(volatile uint32_t *)((b) + (o)))
#define REG16(b, o)   (*(volatile uint16_t *)((b) + (o)))

#define GPIOE_MODER   REG(GPIOE_BASE, 0x00u)
#define GPIOE_OSPEEDR REG(GPIOE_BASE, 0x08u)
#define GPIOE_BSRR    REG(GPIOE_BASE, 0x18u)
#define GPIOE_AFRH    REG(GPIOE_BASE, 0x24u)

#define SPI_CR1       REG16(SPI4_BASE, 0x00u)
#define SPI_CR2       REG16(SPI4_BASE, 0x04u)
#define SPI_SR        REG16(SPI4_BASE, 0x08u)
#define SPI_DR        REG16(SPI4_BASE, 0x0Cu)
#define SPI_SR_TXE    (1u << 1)
#define SPI_SR_RXNE   (1u << 0)

#define CS_PIN        11u                 /* PE11, active-low */
#define CS_ASSERT()   (GPIOE_BSRR = (1u << (CS_PIN + 16u)))   /* drive LOW  */
#define CS_DEASSERT() (GPIOE_BSRR = (1u << CS_PIN))           /* drive HIGH */
#define SPI_FLASH_SIZE 0x200000u          /* 2 MB */

void spi4_init(void)
{
    RCC_AHB1ENR |= (1u << 4);             /* GPIOE */
    RCC_APB2ENR |= (1u << 13);            /* SPI4  */
    (void)RCC_AHB1ENR; (void)RCC_APB2ENR;

    /* PE11 CS: pre-load HIGH (deasserted) while still input, then output. */
    CS_DEASSERT();
    GPIOE_MODER = (GPIOE_MODER & ~(3u << (2u * CS_PIN))) | (1u << (2u * CS_PIN));

    /* PE12 SCK / PE13 MISO / PE14 MOSI: AF5, high speed. */
    GPIOE_OSPEEDR |= (3u << 24) | (3u << 26) | (3u << 28);
    GPIOE_MODER = (GPIOE_MODER & ~((3u << 24) | (3u << 26) | (3u << 28)))
                | (2u << 24) | (2u << 26) | (2u << 28);
    GPIOE_AFRH = (GPIOE_AFRH & ~((0xFu << 16) | (0xFu << 20) | (0xFu << 24)))
               | (5u << 16) | (5u << 20) | (5u << 24);

    /* SPI4: disable, clear, configure (0x304), then enable (0x344) — stock sequence. */
    SPI_CR1 = 0;
    SPI_CR2 = 0;
    (void)SPI_DR; (void)SPI_SR;
    SPI_CR1 = 0x304u;
    SPI_CR2 = 0;
    SPI_CR1 = 0x344u;
}

static uint8_t spi4_xfer(uint8_t b)
{
    while (!(SPI_SR & SPI_SR_TXE)) { }
    SPI_DR = b;
    while (!(SPI_SR & SPI_SR_RXNE)) { }
    return (uint8_t)SPI_DR;
}

int spi4_read(uint32_t addr, uint8_t *dst, uint32_t len)
{
    if (addr >= SPI_FLASH_SIZE || addr + len > SPI_FLASH_SIZE)
        return -1;

    CS_ASSERT();
    (void)spi4_xfer(0x03u);                 /* READ command */
    (void)spi4_xfer((uint8_t)(addr >> 16));
    (void)spi4_xfer((uint8_t)(addr >> 8));
    (void)spi4_xfer((uint8_t)addr);
    for (uint32_t i = 0; i < len; i++)
        dst[i] = spi4_xfer(0x00u);
    CS_DEASSERT();
    return 0;
}
