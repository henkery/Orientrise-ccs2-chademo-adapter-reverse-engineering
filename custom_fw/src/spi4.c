/* spi4.c — SPI4 external-flash read transport (REPORT §5.21 measurement addendum).
 *
 * Faithful replica of the stock SPI4 front-end used to read the factory NV calibration:
 *   - SPI4 init 0x08088C38: CR1 = 0x344 (CPOL=0/CPHA=0 mode 0, master, BR=/2 -> 42 MHz,
 *     8-bit, MSB-first, SSM+SSI, SPE), CR2 = 0. CS = PE11 (software, active-low).
 *   - NV read core 0x08088CFE: assert CS, send READ 0x03 + 24-bit address (MSB first),
 *     clock out `len` bytes with dummy 0x00 writes, deassert CS. 2 MB address space.
 * SCK=PE12 / MISO=PE13 / MOSI=PE14 (AF5).
 *
 * Write path (REPORT §5.15c, revert-from-custom): faithful mirror of the boot update-pool writer
 *   - f+0x1ca4 spi4_cmd:  CS↓ + cmd byte + CS↑ (WREN 0x06).
 *   - f+0x1aa4 spi4_rdsr: CS↓ + 0x05 + read status + CS↑; busy = bit0.
 *   - f+0x1bb2 page program: (addr&0xFF)+len ≤ 0x100; WREN → CS↓ + 0x02 + addr[23:16/15:8/7:0] +
 *     data + CS↑ → poll busy.
 *   - f+0x1c3e sector erase: WREN → CS↓ + 0x20 + addr + CS↑ → poll busy → IWDG feed (f+0x18a2).
 *   - f+0x1b42 spi4_write: page/sector-aware chunking; first sector erased only if sector-aligned,
 *     subsequent sectors always erased. Restricted to the upper-1 MB pool [0x100000,0x200000) so the
 *     lower-1 MB factory NV cal is never touched (boot bounds logical addr < 0x100000).
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
#define SPI_POOL_BASE  0x100000u          /* upper-1 MB update pool (boot logical 0); NV cal below */
#define IWDG_KR       (*(volatile uint32_t *)0x40003000u)
#define IWDG_FEED     0x0000AAAAu         /* watchdog reload; no-op if disabled (boot f+0x18a2) */

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

/* ---- write path (boot f+0x1ca4 / f+0x1aa4 / f+0x1bb2 / f+0x1c3e / f+0x1b42) ---- */

/* f+0x1ca4: CS↓ + single command byte + CS↑ (e.g. WREN 0x06). */
static void spi4_cmd(uint8_t cmd)
{
    CS_ASSERT();
    (void)spi4_xfer(cmd);
    CS_DEASSERT();
}

/* f+0x1aa4: RDSR (0x05) -> status byte; busy = bit0. */
static uint8_t spi4_rdsr(void)
{
    CS_ASSERT();
    (void)spi4_xfer(0x05u);
    uint8_t s = spi4_xfer(0x00u);
    CS_DEASSERT();
    return s;
}

static void spi4_wait_busy(void)
{
    while (spi4_rdsr() & 1u) { }
}

/* f+0x1bb2: page program. Requires (addr&0xFF)+len <= 0x100 (within one 256-byte page).
 * WREN -> CS↓ + 0x02 + addr[23:16/15:8/7:0] + data + CS↑ -> poll busy. */
static int spi4_page_program(uint32_t addr, const uint8_t *src, uint32_t len)
{
    if (addr >= SPI_FLASH_SIZE || (addr & 0xFFu) + len > 0x100u)
        return -1;

    spi4_cmd(0x06u);                        /* WREN */
    CS_ASSERT();
    (void)spi4_xfer(0x02u);                 /* PAGE PROGRAM */
    (void)spi4_xfer((uint8_t)(addr >> 16));
    (void)spi4_xfer((uint8_t)(addr >> 8));
    (void)spi4_xfer((uint8_t)addr);
    for (uint32_t i = 0; i < len; i++)
        (void)spi4_xfer(src[i]);
    CS_DEASSERT();
    spi4_wait_busy();
    return 0;
}

/* f+0x1c3e: 4 KB sector erase at the sector containing `addr`.
 * WREN -> CS↓ + 0x20 + addr[23:16/15:8/7:0] + CS↑ -> poll busy -> IWDG feed (f+0x18a2). */
static int spi4_sector_erase(uint32_t addr)
{
    uint32_t base = addr & ~0xFFFu;
    if (base < SPI_POOL_BASE || base >= SPI_FLASH_SIZE)
        return -1;

    spi4_cmd(0x06u);                        /* WREN */
    CS_ASSERT();
    (void)spi4_xfer(0x20u);                 /* SECTOR ERASE (4 KB) */
    (void)spi4_xfer((uint8_t)(base >> 16));
    (void)spi4_xfer((uint8_t)(base >> 8));
    (void)spi4_xfer((uint8_t)base);
    CS_DEASSERT();
    spi4_wait_busy();
    IWDG_KR = IWDG_FEED;                    /* erase can be slow; keep the watchdog happy */
    return 0;
}

int spi4_write(uint32_t addr, const uint8_t *src, uint32_t len)
{
    /* Pool-only [0x100000,0x200000): mirrors boot f+0x1b42 logical addr < 0x100000. The lower
     * 1 MB factory NV cal is never erased/programmed. */
    if (addr < SPI_POOL_BASE || addr + len > SPI_FLASH_SIZE)
        return -1;
    if (len == 0)
        return 0;

    uint32_t sector_off  = addr & 0xFFFu;
    uint32_t sector_left = 0x1000u - sector_off;
    uint32_t page_left0  = 0x100u - (addr & 0xFFu);
    int first_sector = 1;

    while (len > 0) {
        /* First sector erased only if sector-aligned; subsequent sectors always erased. */
        if (!first_sector || sector_off == 0) {
            if (spi4_sector_erase(addr) != 0)
                return -1;
        }
        first_sector = 0;

        uint32_t chunk = (len > sector_left) ? sector_left : len;
        len -= chunk;
        uint32_t page_left = page_left0;
        while (chunk > 0) {
            uint32_t pl = (chunk > page_left) ? page_left : chunk;
            if (spi4_page_program(addr, src, pl) != 0)
                return -1;
            addr += pl;
            src  += pl;
            chunk -= pl;
            page_left = 0x100u;
        }
        sector_left = 0x1000u;
        page_left0  = 0x100u;
    }
    return 0;
}

int spi4_erase_range(uint32_t addr, uint32_t len)
{
    if (addr < SPI_POOL_BASE || addr + len > SPI_FLASH_SIZE)
        return -1;
    if (len == 0)
        return 0;
    uint32_t base = addr & ~0xFFFu;
    uint32_t end  = addr + len;
    while (base < end) {
        if (spi4_sector_erase(base) != 0)
            return -1;
        base += 0x1000u;
    }
    return 0;
}

int spi4_program(uint32_t addr, const uint8_t *src, uint32_t len)
{
    if (addr < SPI_POOL_BASE || addr + len > SPI_FLASH_SIZE)
        return -1;
    uint32_t page_left = 0x100u - (addr & 0xFFu);
    while (len > 0) {
        uint32_t pl = (len > page_left) ? page_left : len;
        if (spi4_page_program(addr, src, pl) != 0)
            return -1;
        addr += pl;
        src  += pl;
        len  -= pl;
        page_left = 0x100u;
    }
    return 0;
}
