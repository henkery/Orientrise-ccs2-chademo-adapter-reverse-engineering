/* qca7005.h — QCA7005 PLC SPI1 host driver + MME/Ethernet TX/RX transport (REPORT §5.9).
 *
 * Faithful replica of the C013 QCA7005 high-level driver (0x08089010–0x08089708) + the SPI1
 * bit-level primitives (0x08093C66–0x08093F7A), byte-derived and independently verified
 * (.qwen/tmp/ccs2_re/A_qca7005_transport.md, verify_a/verify_a2). The QCA7005 is the HomePlug
 * GreenPHY PLC modem that carries the CCS2 EVCC traffic (SLAC MME + SDP/V2GTP over TCP/IP).
 * The STM32 is the SPI host; the QCA7005 firmware lives in external SPI flash (not flashed).
 *
 * SPI1: PA5 SCK / PA6 MISO / PA7 MOSI (AF5), CS = PA4 (active-low), reset = PC5, IRQ = PC4
 * (input, polled). CR1 = 0x0357 (Mode 3 CPOL=CPHA=1, master, fPCLK2/8, 8-bit, MSB-first,
 * SSM+SSI software-CS, full-duplex), CR2 = 0.
 *
 * SPI slave register protocol: read = CS↓ [0xC0|addr_hi, addr_lo] + 2 dummy clocks → u16 BE;
 * write = CS↓ [0x40|addr_hi, addr_lo, val_hi, val_lo]. Buffer access uses reg 0x100 (cmd 0x4100).
 * Buffer-WRITE: pad-to-60, TX-free reg 0x200 ≥ padded+14, reg 0x100 = padded+10, then CS↓
 * [00,00] + 4×0xAA sync + len(LE) + [00,01] + data + pad + 2×0x55 trailer + CS↑.
 * Buffer-READ: RX-avail reg 0x300, reg 0x100 = n, CS↓ [80,00] + clock out n bytes + CS↑.
 *
 * INERT: this is communication transport only — it brings up the PLC modem, reads its PIB MAC,
 * and sends/receives Ethernet frames. It drives NO power-stage GPIO. The SLAC/SDP/DIN layers
 * above it consume the RX callback + frame_send. Bare-metal single-loop replica: the stock RTOS
 * mutex is unnecessary (no concurrent task); delays use tick_delay_ms; RX is poll-driven (PC4 +
 * reg 0xC00 bit0) from qca7005_service(), mirroring the stock RX task 0x08089486.
 */
#ifndef QCA7005_H
#define QCA7005_H
#include <stdint.h>

/* Ethernet / MME frame layout (built byte-by-byte; 12-byte MAC header template @0x080AFDCC). */
#define QCA_ETH_DEST      0u    /* dest MAC[6]                       */
#define QCA_ETH_SRC       6u    /* src  MAC[6]                       */
#define QCA_ETH_TYPE      12u   /* EtherType u16 BE (0x88E1 MME)     */
#define QCA_MMV           14u   /* management message version = 0    */
#define QCA_MMTYPE_LO     15u   /* MMTYPE low byte                   */
#define QCA_MMTYPE_HI     16u   /* MMTYPE high byte (LE in frame)    */
#define QCA_PAYLOAD       17u   /* MME payload                       */
#define QCA_ETHTYPE_MME   0x88E1u
#define QCA_MAC_LEN       6u
#define QCA_ETH_MIN_FRAME 60u   /* Ethernet minimum frame (pad below) */
#define QCA_MAX_FRAME     1518u

/* QCA7005 SPI registers (addresses/values decoded; semantic names inferred ~). */
#define QCA_REG_BUF_CMD     0x0100u  /* ~buffer-access command/length trigger (cmd 0x4100) */
#define QCA_REG_TX_FREE     0x0200u  /* ~TX-buffer free space (bytes)                      */
#define QCA_REG_RX_AVAIL    0x0300u  /* ~RX-buffer available bytes                         */
#define QCA_REG_SPI_RST     0x0400u  /* ~SPI reset/control (init 0x80)                     */
#define QCA_REG_INT_STATUS  0x0C00u  /* ~interrupt enable/status (init 0x447)              */
#define QCA_REG_INT_TIMEOUT 0x0D00u  /* ~interrupt timeout/enable (init 0x41)              */
#define QCA_REG_SPI_CFG     0x1200u  /* ~SPI config (init 0xC5B)                           */
#define QCA_REG_CPU_READY   0x1A00u  /* ~CPU-ready signature (must read 0xAA55)            */
#define QCA_REG_SIG_CLEAR   0x1B00u  /* ~signature/scratch clear (init 0)                  */
#define QCA_CPU_READY_SIG   0xAA55u
#define QCA_INT_RX_AVAIL    (1u << 0)  /* reg 0xC00 bit0 = RX packet available */
#define QCA_INT_CPU_READY   (1u << 6)  /* reg 0xC00 bit6 = CPU-ready / re-init */

/* RX ring buffer (stock @0x20022961, 4096 B). Packet header: [L:4 BE][0xAAAAAAAB:4][fp=L-10:2]
 * [rsv:2], frame @+0xC, total packet bytes sl=L+4, validate fp+14==sl && L-0x18<=1508. */
#define QCA_RX_RING_SIZE  4096u
#define QCA_PKT_MAGIC     0xAAAAAAABu
#define QCA_PKT_HDR_LEN   12u
#define QCA_PKT_MAX_L     (1508u + 0x18u)  /* L-0x18 <= 1508 */

/* MAC-read MME (vendor 0xA000 REQ / 0xA001 CNF): param 0xB000 (PIB MAC) + op 'R' + 4 zero. */
#define QCA_MMTYPE_MAC_READ_REQ 0xA000u
#define QCA_MMTYPE_MAC_READ_CNF 0xA001u
#define QCA_MAC_READ_LEN        24u
#define QCA_PIB_MAC_PARAM       0xB000u
#define QCA_MAC_CNF_DONE        0x55u   /* done marker written to CNF status byte */

/* RX callback: invoked per received Ethernet frame (frame ptr, frame length). */
typedef void (*qca7005_rx_cb)(const uint8_t *frame, uint16_t len);

/* Bring up SPI1 + QCA7005: GPIO/CR1 init, PC5 reset pulse, CPU-ready poll, reg-init, MAC-read.
 * Returns 0 on success (MAC read), non-zero on failure (no modem / timeout). Blocking (stock
 * timeouts: CPU-ready sig 400×10 ms, bit6 1000×10 ms, MAC-read 20×10 ms ×3). */
int  qca7005_init(void);
void qca7005_set_rx_cb(qca7005_rx_cb cb);
/* Idle hook invoked inside the blocking bring-up delays (bu_delay) so another subsystem (the USB
 * CDC revert console) can be serviced while the modem CPU-ready/MAC polls run. NULL = no-op. Set
 * before qca7005_init; the hook must be safe to call from the bring-up context (interrupts on). */
void qca7005_set_idle_hook(void (*fn)(void));
/* Send an Ethernet frame (mutex-free buf-WRITE). Returns 0 ok, 1 if no TX space. */
int  qca7005_frame_send(const uint8_t *frame, uint16_t len);
/* Drain the RX ring, parse packets, invoke the RX callback per frame. Returns bytes read. */
int  qca7005_rx_dispatch(void);
/* Poll PC4 + reg 0xC00: re-init on bit6, drain RX on bit0 (mirrors stock RX task). Call each tick. */
void qca7005_service(void);
/* 6-byte PIB MAC read from the modem (NULL if MAC-read failed). */
const uint8_t *qca7005_mac(void);
/* Last bring-up result (bench QCA diag): 0 ok / 1 sig timeout / 2 bit6 timeout / 3 MAC-read fail /
 * 4 reg-init sig mismatch / -1 not run. */
int qca7005_init_rc(void);
/* Bench MAC-read probe: re-send the MAC-read REQ, poll 1 s, capture the first raw CNF frame.
 * Returns -1 no TX space / 0 silent / 1 frame received. Sets mac_valid if the CNF validates. */
int qca7005_mac_probe(void);
/* Raw frame captured by the last qca7005_mac_probe (up to 64 B); *len = bytes captured (0 if none). */
const uint8_t *qca7005_mac_probe_resp(uint16_t *len);
/* Direct SPI register access (for upper-layer diagnostics / SLAC). */
uint16_t qca7005_reg_read(uint16_t addr);
void     qca7005_reg_write(uint16_t addr, uint16_t val);

/* ---- pure, host-testable helpers (no hardware) ---- */
/* Build the 24-byte MAC-read REQ (0xA000) into frame[24]. Returns 24. */
uint16_t qca7005_build_mac_req(uint8_t *frame);
/* Validate a MAC-read CNF (0xA001): EtherType 0x88E1, dest==host-src, MMTYPE 0xA001, status==0.
 * Returns 1 if valid (caller then sets the done marker + copies the MAC). */
int qca7005_mac_cnf_valid(const uint8_t *frame, uint16_t len);
/* Validate an RX packet header (12 bytes): magic 0xAAAAAAAB, fp==L-10, fp+14==L+4, L-0x18<=1508.
 * On success writes *frame_len (fp) and *pkt_len (sl=L+4), returns 1; else 0. */
int qca7005_pkt_check(const uint8_t *hdr, uint16_t *frame_len, uint16_t *pkt_len);

#endif /* QCA7005_H */
