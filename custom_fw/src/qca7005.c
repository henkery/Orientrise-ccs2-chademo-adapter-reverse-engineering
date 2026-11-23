/* qca7005.c — QCA7005 PLC SPI1 host driver + MME/Ethernet transport (REPORT §5.9).
 * Faithful C013 replica, byte-derived + independently verified (A_qca7005_transport.md,
 * verify_a/verify_a2). High-level driver 0x08089010–0x08089708; SPI1 primitives
 * 0x08093C66–0x08093F7A. INERT communication transport — drives NO power-stage GPIO.
 *
 * Bare-metal single-loop simplifications (vs the stock RTOS): no mutex (no concurrent task),
 * tick_delay_ms for the stock 10 ms delays, RX polled from qca7005_service() (stock RX task
 * 0x08089486 polls PC4 + reg 0xC00). The SPI transactions, register protocol, buffer framing,
 * reg-init values, CPU-ready poll, reset pulse and MAC-read MME are byte-faithful.
 */
#include "qca7005.h"
#include "tick.h"
#include "uart_dbg.h"   /* TEMP debug: stage markers to localize the bring-up stall */

#define IWDG_KR       (*(volatile uint32_t *)0x40003000u)
/* Bring-up delay: feed the IWDG (harmless if disabled) so the blocking modem poll cannot trip
 * the watchdog when the boot left it running; the stock RTOS feeds it in the idle task. Needs
 * tick_init() + interrupts enabled first (tick_delay_ms waits on the SysTick ISR counter).
 * The idle hook (set by main to usb_cdc_task) keeps the USB CDC revert console enumerating during
 * the potentially long modem bring-up, so CDC is available even if the modem is slow/absent. */
static void (*idle_hook)(void);
static void bu_delay(uint32_t ms) { IWDG_KR = 0x0000AAAAu; uart_dbg_poll_reset(); if (idle_hook) idle_hook(); tick_delay_ms(ms); }

#define RCC_AHB1ENR   (*(volatile uint32_t *)0x40023830u)
#define RCC_APB2ENR   (*(volatile uint32_t *)0x40023844u)
#define GPIOA_BASE    0x40020000u
#define GPIOC_BASE    0x40020800u
#define SPI1_BASE     0x40013000u
#define REG(b, o)     (*(volatile uint32_t *)((b) + (o)))
#define REG16(b, o)   (*(volatile uint16_t *)((b) + (o)))

#define GPIOA_MODER   REG(GPIOA_BASE, 0x00u)
#define GPIOA_OSPEEDR REG(GPIOA_BASE, 0x08u)
#define GPIOA_BSRR    REG(GPIOA_BASE, 0x18u)
#define GPIOA_AFRL    REG(GPIOA_BASE, 0x20u)
#define GPIOC_MODER   REG(GPIOC_BASE, 0x00u)
#define GPIOC_BSRR    REG(GPIOC_BASE, 0x18u)
#define GPIOC_IDR     REG(GPIOC_BASE, 0x10u)

#define SPI_CR1       REG16(SPI1_BASE, 0x00u)
#define SPI_CR2       REG16(SPI1_BASE, 0x04u)
#define SPI_SR        REG16(SPI1_BASE, 0x08u)
#define SPI_DR        REG16(SPI1_BASE, 0x0Cu)
#define SPI_SR_TXE    (1u << 1)
#define SPI_SR_RXNE   (1u << 0)

/* CS = PA4 active-low: BSRR BS4 (0x10) = HIGH/deassert, BR4 (0x00100000) = LOW/assert.
 * (Stock computes BR4 as GPIOA_base<<3 = 0x40020000<<3 = 0x00100000.) */
#define CS_ASSERT()   (GPIOA_BSRR = 0x00100000u)
#define CS_DEASSERT() (GPIOA_BSRR = 0x00000010u)
/* Reset = PC5: BR5 (0x200000) = LOW, BS5 (0x20) = HIGH. IRQ = PC4 (IDR bit4). */
#define RESET_LOW()   (GPIOC_BSRR = 0x00200000u)
#define RESET_HIGH()  (GPIOC_BSRR = 0x00000020u)
#define IRQ_LEVEL()   ((GPIOC_IDR >> 4) & 1u)

/* 12-byte MAC header template @0x080AFDCC: dest PIB MAC, src host MAC. */
static const uint8_t mac_hdr_template[12] = {
    0x00, 0xB0, 0x52, 0x00, 0x00, 0x01,   /* dest = 00:B0:52:00:00:01 (PIB MAC) */
    0xFE, 0xFF, 0xFE, 0xFF, 0x00, 0x01    /* src  = FE:FF:FE:FF:00:01 (host)    */
};
#define HOST_MAC (&mac_hdr_template[6])

/* Driver state (mirrors stock ctx 0x20000A30 + MAC resp buf 0x20022838 + ring 0x20022961). */
static uint8_t  mac_resp[297];          /* MAC-read CNF response buffer (stock 0x20022838) */
static uint8_t  mac_addr[QCA_MAC_LEN];  /* resolved PIB MAC (stock 0x2002283E = resp+6)    */
static uint8_t  mac_valid;
static uint8_t  rx_ring[QCA_RX_RING_SIZE];
static uint16_t rx_offset;              /* ring write offset (stock ctx+4)                 */
static uint8_t  rx_poll_cnt;            /* stock ctx+1                                     */
static qca7005_rx_cb rx_cb;
static uint8_t  mac_cnf_seen;           /* internal validator done flag                    */
static int      init_rc = -1;           /* last qca7005_init result (bench diag: -1 unrun) */

/* ---- SPI1 byte exchange (full-duplex, 8-bit, Mode 3) ---- */
static uint8_t spi1_xfer(uint8_t b)
{
    while (!(SPI_SR & SPI_SR_TXE)) { }
    SPI_DR = b;
    while (!(SPI_SR & SPI_SR_RXNE)) { }
    return (uint8_t)SPI_DR;
}

/* ---- SPI register access (read cmd 0xC000|addr, write cmd 0x4000|addr) ---- */
uint16_t qca7005_reg_read(uint16_t addr)
{
    uint16_t cmd = 0xC000u | addr;
    CS_ASSERT();
    (void)spi1_xfer((uint8_t)(cmd >> 8));
    (void)spi1_xfer((uint8_t)(cmd & 0xFFu));
    uint8_t hi = spi1_xfer(0x00u);
    uint8_t lo = spi1_xfer(0x00u);
    CS_DEASSERT();
    return (uint16_t)((hi << 8) | lo);
}

void qca7005_reg_write(uint16_t addr, uint16_t val)
{
    uint16_t cmd = 0x4000u | addr;
    CS_ASSERT();
    (void)spi1_xfer((uint8_t)(cmd >> 8));
    (void)spi1_xfer((uint8_t)(cmd & 0xFFu));
    (void)spi1_xfer((uint8_t)(val >> 8));
    (void)spi1_xfer((uint8_t)(val & 0xFFu));
    CS_DEASSERT();
}

/* ---- SPI buffer-WRITE (0x08093DA8): pad-to-60 + 0xAA sync framed payload + 0x55 trailer ---- */
static int spi_buf_write(const uint8_t *src, uint16_t len)
{
    uint16_t padded = len;
    uint16_t pad = 0;
    if (len < QCA_ETH_MIN_FRAME) {
        pad = (uint16_t)(QCA_ETH_MIN_FRAME - len);
        padded = QCA_ETH_MIN_FRAME;
    }
    uint16_t free_sp = qca7005_reg_read(QCA_REG_TX_FREE);
    if (free_sp < (uint16_t)(padded + 14u))
        return 1;                                   /* no TX space */

    qca7005_reg_write(QCA_REG_BUF_CMD, (uint16_t)(padded + 10u));  /* header cmd 0x4100 */

    CS_ASSERT();
    (void)spi1_xfer(0x00u);                         /* 2 turnaround dummy bytes */
    (void)spi1_xfer(0x00u);
    for (int i = 0; i < 4; i++)                     /* 4×0xAA sync preamble */
        (void)spi1_xfer(0xAAu);
    (void)spi1_xfer((uint8_t)(padded & 0xFFu));     /* length, little-endian */
    (void)spi1_xfer((uint8_t)(padded >> 8));
    (void)spi1_xfer(0x00u);                         /* [00,01] */
    (void)spi1_xfer(0x01u);
    for (uint16_t i = 0; i < len; i++)              /* frame data */
        (void)spi1_xfer(src[i]);
    for (uint16_t i = 0; i < pad; i++)              /* pad to Ethernet minimum */
        (void)spi1_xfer(0x00u);
    (void)spi1_xfer(0x55u);                         /* 2×0x55 trailer */
    (void)spi1_xfer(0x55u);
    CS_DEASSERT();
    return 0;
}

/* ---- SPI buffer-READ (0x08093D44): RX-avail reg 0x300, clock out n bytes ---- */
static uint16_t spi_buf_read(uint8_t *dst, uint16_t max)
{
    uint16_t avail = qca7005_reg_read(QCA_REG_RX_AVAIL);
    uint16_t n = (avail < max) ? avail : max;
    if (n == 0)
        return 0;
    qca7005_reg_write(QCA_REG_BUF_CMD, n);
    CS_ASSERT();
    (void)spi1_xfer(0x80u);                         /* 2 turnaround dummy bytes */
    (void)spi1_xfer(0x00u);
    for (uint16_t i = 0; i < n; i++)
        dst[i] = spi1_xfer(0x00u);
    CS_DEASSERT();
    return n;
}

/* ---- pure helpers (host-testable) ---- */
uint16_t qca7005_build_mac_req(uint8_t *frame)
{
    for (int i = 0; i < 12; i++)
        frame[i] = mac_hdr_template[i];
    frame[QCA_ETH_TYPE]     = (uint8_t)(QCA_ETHTYPE_MME >> 8);   /* 0x88 */
    frame[QCA_ETH_TYPE + 1] = (uint8_t)(QCA_ETHTYPE_MME & 0xFFu);/* 0xE1 */
    frame[QCA_MMV]       = 0x00u;
    frame[QCA_MMTYPE_LO] = (uint8_t)(QCA_MMTYPE_MAC_READ_REQ & 0xFFu);  /* 0x00 */
    frame[QCA_MMTYPE_HI] = (uint8_t)(QCA_MMTYPE_MAC_READ_REQ >> 8);     /* 0xA0 */
    frame[QCA_PAYLOAD]     = (uint8_t)(QCA_PIB_MAC_PARAM & 0xFFu);      /* 0x00 */
    frame[QCA_PAYLOAD + 1] = (uint8_t)(QCA_PIB_MAC_PARAM >> 8);         /* 0xB0 */
    frame[QCA_PAYLOAD + 2] = 0x52u;                                     /* 'R' read op */
    frame[QCA_PAYLOAD + 3] = 0x00u;
    frame[QCA_PAYLOAD + 4] = 0x00u;
    frame[QCA_PAYLOAD + 5] = 0x00u;
    frame[QCA_PAYLOAD + 6] = 0x00u;
    return QCA_MAC_READ_LEN;
}

int qca7005_mac_cnf_valid(const uint8_t *frame, uint16_t len)
{
    if (len < QCA_MAC_READ_LEN) return 0;
    /* EtherType == 0x88E1 (on-wire 88 E1) */
    if (frame[QCA_ETH_TYPE] != 0x88u || frame[QCA_ETH_TYPE + 1] != 0xE1u) return 0;
    /* dest == host src MAC (FE:FF:FE:FF:00:01) — the CNF is addressed back to the host */
    for (uint16_t i = 0; i < QCA_MAC_LEN; i++)
        if (frame[QCA_ETH_DEST + i] != HOST_MAC[i]) return 0;
    /* MMTYPE == 0xA001 CNF */
    if (frame[QCA_MMTYPE_LO] != 0x01u || frame[QCA_MMTYPE_HI] != 0xA0u) return 0;
    /* status/done byte == 0 (success) */
    if (frame[0x14] != 0x00u) return 0;
    return 1;
}

int qca7005_pkt_check(const uint8_t *hdr, uint16_t *frame_len, uint16_t *pkt_len)
{
    uint32_t L = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                 ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];          /* big-endian */
    uint32_t magic = ((uint32_t)hdr[4] << 24) | ((uint32_t)hdr[5] << 16) |
                     ((uint32_t)hdr[6] << 8) | (uint32_t)hdr[7];
    uint16_t fp = (uint16_t)(((uint16_t)hdr[8] << 8) | hdr[9]);        /* fp = L - 10 */
    if (magic != QCA_PKT_MAGIC) return 0;
    if (L < 0x18u || (L - 0x18u) > 1508u) return 0;
    if (fp != (uint16_t)(L - 10u)) return 0;
    uint32_t sl = L + 4u;                                             /* total packet bytes */
    if ((uint32_t)fp + 14u != sl) return 0;
    *frame_len = fp;
    *pkt_len = (uint16_t)sl;
    return 1;
}

/* ---- reg-init (0x08089422): CPU-ready signature + 5 config register writes ---- */
static int qca_reg_init(void)
{
    rx_offset = 0;
    (void)qca7005_reg_read(QCA_REG_CPU_READY);      /* first two reads discarded */
    (void)qca7005_reg_read(QCA_REG_CPU_READY);
    uint16_t sig = qca7005_reg_read(QCA_REG_CPU_READY);
    if (sig != QCA_CPU_READY_SIG)
        return 4;
    qca7005_reg_write(QCA_REG_SPI_RST,     0x0080u);
    qca7005_reg_write(QCA_REG_SIG_CLEAR,   0x0000u);
    qca7005_reg_write(QCA_REG_SPI_CFG,     0x0C5Bu);
    qca7005_reg_write(QCA_REG_INT_STATUS,  0x0447u);
    qca7005_reg_write(QCA_REG_INT_TIMEOUT, 0x0041u);
    return 0;
}

/* ---- MAC-read CNF validator (internal RX callback, 0x080894EE) ---- */
static void mac_cnf_callback(const uint8_t *frame, uint16_t len)
{
    if (!qca7005_mac_cnf_valid(frame, len))
        return;
    mac_cnf_seen = 1;
    for (uint16_t i = 0; i < len && i < sizeof(mac_resp); i++)
        mac_resp[i] = frame[i];
    mac_resp[0x14] = QCA_MAC_CNF_DONE;              /* set done marker 0x55 */
    for (uint16_t i = 0; i < QCA_MAC_LEN; i++)           /* PIB MAC = CNF src-MAC field */
        mac_addr[i] = frame[QCA_ETH_SRC + i];
    mac_valid = 1;
}

/* ---- MAC-read REQ build+send (0x0808955C) + CNF poll (0x08089532, 20×10 ms) ---- */
static int qca_mac_read(void)
{
    uint8_t req[QCA_MAC_READ_LEN];
    qca7005_build_mac_req(req);
    for (uint16_t i = 0; i < sizeof(mac_resp); i++)
        mac_resp[i] = 0;
    mac_cnf_seen = 0;

    qca7005_rx_cb save = rx_cb;
    rx_cb = mac_cnf_callback;
    if (qca7005_frame_send(req, QCA_MAC_READ_LEN) != 0) {
        rx_cb = save;
        return 1;
    }
    for (int i = 0; i < 20; i++) {                  /* 20 × 10 ms */
        bu_delay(10);
        (void)qca7005_rx_dispatch();
        if (mac_cnf_seen && mac_resp[0x14] == QCA_MAC_CNF_DONE) {
            rx_cb = save;
            return 0;
        }
    }
    rx_cb = save;
    return 1;
}

/* ---- CPU-ready poll (0x080895A8): sig 400×10 ms, bit6 1000×10 ms, reg-init, MAC-read ×3 ---- */
static int qca_cpu_ready(void)
{
    uart_dbg_puts("QSIG\r\n");                 /* TEMP debug: entering sig poll */
    int sig_ok = 0;
    for (int i = 0; i < 400; i++) {
        (void)qca7005_reg_read(QCA_REG_CPU_READY);  /* first read discarded */
        if (qca7005_reg_read(QCA_REG_CPU_READY) == QCA_CPU_READY_SIG) { sig_ok = 1; break; }
        bu_delay(10);
    }
    uart_dbg_puts(sig_ok ? "QSOK\r\n" : "QSTO\r\n");  /* TEMP debug: sig poll done */
    if (!sig_ok) return 1;

    uart_dbg_puts("QBIT\r\n");                 /* TEMP debug: entering bit6 poll */
    int ready = 0;
    for (int i = 0; i < 1000; i++) {
        if (qca7005_reg_read(QCA_REG_INT_STATUS) & QCA_INT_CPU_READY) { ready = 1; break; }
        bu_delay(10);
    }
    if (!ready) return 2;

    uart_dbg_puts("QINI\r\n");                 /* TEMP debug: reg-init */
    int rc = qca_reg_init();
    if (rc != 0) return rc;

    uart_dbg_puts("QMAC\r\n");                 /* TEMP debug: MAC-read */
    for (int i = 0; i < 3; i++) {                   /* MAC-read ×3 retries */
        if (qca_mac_read() == 0) return 0;
    }
    return 3;
}

/* ---- GPIO + SPI1 init (stock board init 0x08087A24 + SPI-open 0x08093CA0) ---- */
static void qca_spi_init(void)
{
    RCC_AHB1ENR |= (1u << 0) | (1u << 2);           /* GPIOA + GPIOC */
    RCC_APB2ENR |= (1u << 12);                      /* SPI1 */
    (void)RCC_AHB1ENR; (void)RCC_APB2ENR;

    /* PA4 CS: pre-load HIGH (deasserted) while input, then output. */
    CS_DEASSERT();
    GPIOA_MODER = (GPIOA_MODER & ~(3u << 8)) | (1u << 8);          /* PA4 output */
    /* PA5/6/7 SCK/MISO/MOSI: AF5, high speed. */
    GPIOA_OSPEEDR |= (3u << 10) | (3u << 12) | (3u << 14);
    GPIOA_MODER = (GPIOA_MODER & ~((3u << 10) | (3u << 12) | (3u << 14)))
                | (2u << 10) | (2u << 12) | (2u << 14);
    GPIOA_AFRL = (GPIOA_AFRL & ~((0xFu << 20) | (0xFu << 24) | (0xFu << 28)))
               | (5u << 20) | (5u << 24) | (5u << 28);

    /* PC5 reset: pre-load HIGH, then output. PC4 IRQ: input (reset state). */
    RESET_HIGH();
    GPIOC_MODER = (GPIOC_MODER & ~(3u << 10)) | (1u << 10);        /* PC5 output */
    GPIOC_MODER &= ~(3u << 8);                                     /* PC4 input  */

    /* SPI1: disable, clear, configure (0x317), then enable (0x357) — stock sequence. */
    SPI_CR1 = 0;
    SPI_CR2 = 0;
    (void)SPI_DR; (void)SPI_SR;
    SPI_CR1 = 0x0317u;
    SPI_CR2 = 0;
    SPI_CR1 = 0x0357u;
}

int qca7005_init(void)
{
    mac_valid = 0;
    rx_offset = 0;
    rx_poll_cnt = 0;
    rx_cb = 0;
    qca_spi_init();
    uart_dbg_puts("QSPI\r\n");                 /* TEMP debug: SPI1 configured */

    /* PC5 reset pulse: low 2 ms → high 2 ms (stock 0x08089624), then CPU-ready bring-up. */
    RESET_LOW();
    IWDG_KR = 0x0000AAAAu;
    uart_dbg_puts("R1\r\n");                   /* TEMP debug: before idle_hook */
    if (idle_hook) idle_hook();
    uart_dbg_puts("R2\r\n");                   /* TEMP debug: after idle_hook, before tick_delay */
    tick_delay_ms(2);
    uart_dbg_puts("R3\r\n");                   /* TEMP debug: after tick_delay */
    RESET_HIGH();
    bu_delay(2);
    uart_dbg_puts("QRST\r\n");                 /* TEMP debug: reset pulse delays returned */
    init_rc = qca_cpu_ready();
    return init_rc;
}

void qca7005_set_rx_cb(qca7005_rx_cb cb) { rx_cb = cb; }

void qca7005_set_idle_hook(void (*fn)(void)) { idle_hook = fn; }

int qca7005_frame_send(const uint8_t *frame, uint16_t len)
{
    if (len == 0 || len > QCA_MAX_FRAME) return 1;
    return spi_buf_write(frame, len);
}

const uint8_t *qca7005_mac(void) { return mac_valid ? mac_addr : 0; }

/* Last bring-up result for the bench QCA diagnostic: 0 ok / 1 sig-poll timeout / 2 bit6 timeout /
 * 3 MAC-read failed / 4 reg-init sig mismatch / -1 init not run. */
int qca7005_init_rc(void) { return init_rc; }

/* ---- RX ring dispatch (0x0808938A): read ring, parse packets, invoke callback ---- */
int qca7005_rx_dispatch(void)
{
    uint16_t space = (uint16_t)(QCA_RX_RING_SIZE - rx_offset);
    uint16_t got = spi_buf_read(&rx_ring[rx_offset], space);
    if (got == 0) return 0;
    uint16_t end = (uint16_t)(rx_offset + got);

    uint16_t pos = 0;
    while ((uint16_t)(end - pos) >= QCA_PKT_HDR_LEN) {
        uint16_t frame_len, pkt_len;
        if (!qca7005_pkt_check(&rx_ring[pos], &frame_len, &pkt_len))
            break;                                  /* invalid/partial header -> stop */
        if ((uint32_t)pos + pkt_len > end)
            break;                                  /* partial packet -> keep for next read */
        const uint8_t *frame = &rx_ring[pos + QCA_PKT_HDR_LEN];
        if (rx_cb) rx_cb(frame, frame_len);
        pos = (uint16_t)(pos + pkt_len);
    }
    /* move leftover partial packet to ring start (stock memmove) */
    uint16_t left = (uint16_t)(end - pos);
    for (uint16_t i = 0; i < left; i++)
        rx_ring[i] = rx_ring[pos + i];
    rx_offset = left;
    return got;
}

/* ---- RX service (stock RX task 0x08089486): poll PC4 + reg 0xC00 ---- */
void qca7005_service(void)
{
    rx_poll_cnt++;
    if (IRQ_LEVEL()) {
        uint16_t st = qca7005_reg_read(QCA_REG_INT_STATUS);
        if (st & QCA_INT_CPU_READY)                 /* bit6: modem re-init required */
            (void)qca_reg_init();
        if (st & QCA_INT_RX_AVAIL) {                /* bit0: drain RX */
            while (qca7005_rx_dispatch() != 0) { }
            rx_poll_cnt = 0;
        }
    } else if (rx_poll_cnt >= 10u) {                /* idle: periodic drain every 10 polls */
        rx_poll_cnt = 0;
        while (qca7005_rx_dispatch() != 0) { }
    }
}
