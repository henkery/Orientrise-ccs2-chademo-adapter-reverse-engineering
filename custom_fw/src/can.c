/* can.c — bxCAN CAN1 transport (REPORT §5.8.2). Register values byte-derived from the stock
 * CAN-open init arm: MCR=0x4D (INRQ|TXFP|RFLM|AWUM), BTR=0x00270006 (500k @ 42 MHz APB1),
 * filters via the shared CAN1 filter bank (CAN2SB=14). CAN1-only board (PD0/PD1 AF9).
 * RX is interrupt-driven (FIFO0 pending), TX polled across the 3 mailboxes. INERT: no GPIO
 * power-stage drive here — communication only.
 */
#include "can.h"
#include "rcc.h"

#define CAN1_BASE   0x40006400u
#define REG(off)    (*(volatile uint32_t *)(CAN1_BASE + (off)))
#define CAN_MCR     REG(0x00u)
#define CAN_MSR     REG(0x04u)
#define CAN_TSR     REG(0x08u)
#define CAN_RF0R    REG(0x0Cu)
#define CAN_IER     REG(0x14u)
#define CAN_ESR     REG(0x18u)
#define CAN_BTR     REG(0x1Cu)
#define CAN_TIxR(x)  REG(0x180u + (x) * 0x10u)
#define CAN_TDTxR(x) REG(0x184u + (x) * 0x10u)
#define CAN_TDLxR(x) REG(0x188u + (x) * 0x10u)
#define CAN_TDHxR(x) REG(0x18Cu + (x) * 0x10u)
#define CAN_RI0R    REG(0x1B0u)
#define CAN_RDT0R   REG(0x1B4u)
#define CAN_RDL0R   REG(0x1B8u)
#define CAN_RDH0R   REG(0x1BCu)
#define CAN_FMR     REG(0x200u)
#define CAN_FM1R    REG(0x204u)
#define CAN_FS1R    REG(0x20Cu)
#define CAN_FFA1R   REG(0x214u)
#define CAN_FA1R    REG(0x21Cu)
#define CAN_FR1(b)  REG(0x240u + (b) * 8u)
#define CAN_FR2(b)  REG(0x244u + (b) * 8u)

#define MCR_INRQ    (1u << 0)
#define MCR_SLEEP   (1u << 1)
#define MSR_INAK    (1u << 0)
#define MSR_SLAK    (1u << 1)
#define IER_FMPIE0  (1u << 1)
#define RF0R_FMP0   (3u << 0)
#define RF0R_RFOM0  (1u << 5)
#define TSR_TME0    (1u << 26)
#define TSR_TME1    (1u << 27)
#define TSR_TME2    (1u << 28)
#define ESR_BOFF    (1u << 2)
#define TI_TXRQ     (1u << 0)
#define TI_IDE      (1u << 2)

#define RCC_APB1ENR  (*(volatile uint32_t *)0x40023840u)
#define RCC_APB1ENR_CAN1EN (1u << 25)
#define GPIOD_BASE   0x40020C00u
#define GPIOD_MODER  (*(volatile uint32_t *)(GPIOD_BASE + 0x00u))
#define GPIOD_OSPEEDR (*(volatile uint32_t *)(GPIOD_BASE + 0x08u))
#define GPIOD_PUPDR  (*(volatile uint32_t *)(GPIOD_BASE + 0x0Cu))
#define GPIOD_AFRL   (*(volatile uint32_t *)(GPIOD_BASE + 0x20u))
#define NVIC_ISER0   (*(volatile uint32_t *)0xE000E100u)
#define NVIC_ICER0   (*(volatile uint32_t *)0xE000E180u)
#define CAN1_RX0_IRQn 20u

/* RX ring buffer (ISR produces, main consumes). Power-of-two depth for cheap wrap. */
#define RX_RING_DEPTH 16u
#define RX_RING_MASK  (RX_RING_DEPTH - 1u)
static can_frame_t rx_ring[RX_RING_DEPTH];
static volatile uint32_t rx_head;   /* ISR write index */
static volatile uint32_t rx_tail;   /* main read index */

static uint32_t pack_data_lo(const uint8_t d[8])
{
    return (uint32_t)d[0] | ((uint32_t)d[1] << 8) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
}
static uint32_t pack_data_hi(const uint8_t d[8])
{
    return (uint32_t)d[4] | ((uint32_t)d[5] << 8) | ((uint32_t)d[6] << 16) | ((uint32_t)d[7] << 24);
}

void CAN1_RX0_IRQHandler(void)
{
    while (CAN_RF0R & RF0R_FMP0) {
        uint32_t ri = CAN_RI0R;
        uint32_t rdt = CAN_RDT0R;
        uint32_t lo = CAN_RDL0R;
        uint32_t hi = CAN_RDH0R;
        CAN_RF0R = RF0R_RFOM0;   /* release FIFO0 output mailbox */

        uint32_t next = (rx_head + 1u) & RX_RING_MASK;
        if (next != rx_tail) {   /* drop frame if ring full (keep newest unread) */
            can_frame_t *f = &rx_ring[rx_head];
            f->ide = (ri & TI_IDE) ? 1u : 0u;
            f->id  = f->ide ? ((ri >> 3) & 0x1FFFFFFFu) : ((ri >> 21) & 0x7FFu);
            f->dlc = (uint8_t)(rdt & 0xFu);
            if (f->dlc > 8u) f->dlc = 8u;
            f->data[0] = (uint8_t)lo;        f->data[1] = (uint8_t)(lo >> 8);
            f->data[2] = (uint8_t)(lo >> 16); f->data[3] = (uint8_t)(lo >> 24);
            f->data[4] = (uint8_t)hi;        f->data[5] = (uint8_t)(hi >> 8);
            f->data[6] = (uint8_t)(hi >> 16); f->data[7] = (uint8_t)(hi >> 24);
            rx_head = next;
        }
    }
}

void can_init(void)
{
    /* CAN1 clock + PD0(RX)/PD1(TX) AF9, high-speed, no pull. */
    RCC_APB1ENR |= RCC_APB1ENR_CAN1EN;
    (void)RCC_APB1ENR;
    GPIOD_MODER   = (GPIOD_MODER & ~0xFu) | 0xAu;          /* PD0/PD1 -> alternate function (10) */
    GPIOD_OSPEEDR = (GPIOD_OSPEEDR & ~0xFu) | 0xFu;        /* high speed (50 MHz) */
    GPIOD_PUPDR   = (GPIOD_PUPDR & ~0xFu);                 /* no pull */
    GPIOD_AFRL    = (GPIOD_AFRL & ~0xFFu) | 0x99u;         /* AF9 on PD0/PD1 */

    /* Enter init mode (stock MCR=0x4D: INRQ|TXFP|RFLM|AWUM), wait INAK. */
    CAN_MCR = 0x4Du;
    while (!(CAN_MSR & MSR_INAK)) { }
    CAN_MCR &= ~MCR_SLEEP;                                 /* ensure not asleep */

    CAN_BTR = CAN_BTR_500K;                                /* 500 kbit/s, 75% sample point */
    CAN_IER = IER_FMPIE0;                                  /* FIFO0-message-pending interrupt */

    /* Acceptance filter: bank 0, 32-bit mask mode, accept standard IDs 0x100..0x103
     * (H100/H101/H102) as data frames -> FIFO0. CAN2SB=14 (CAN1 owns banks 0..13). */
    CAN_FMR   = (1u << 0) | (14u << 8);                    /* FINIT + CAN2SB=14 */
    CAN_FM1R  = 0u;                                        /* mask mode */
    CAN_FS1R  = (1u << 0);                                 /* bank 0 = 32-bit scale */
    CAN_FFA1R = 0u;                                        /* all -> FIFO0 */
    CAN_FR1(0) = (0x100u << 21);                           /* STID=0x100, IDE=0, RTR=0 */
    CAN_FR2(0) = (0x7FCu << 21) | (1u << 2) | (1u << 1);   /* mask STID[10:2], require IDE=0/RTR=0 */
    CAN_FA1R  = (1u << 0);                                 /* activate bank 0 */
    CAN_FMR  &= ~(1u << 0);                                /* leave filter init */

    /* Leave CAN init mode, wait INAK clear. */
    CAN_MCR &= ~MCR_INRQ;
    while (CAN_MSR & MSR_INAK) { }

    rx_head = 0; rx_tail = 0;
    NVIC_ISER0 = (1u << CAN1_RX0_IRQn);                    /* enable CAN1_RX0 interrupt */
}

int can_send(const can_frame_t *f)
{
    uint32_t tsr = CAN_TSR;
    int mb;
    if (tsr & TSR_TME0)      mb = 0;
    else if (tsr & TSR_TME1) mb = 1;
    else if (tsr & TSR_TME2) mb = 2;
    else return -1;                                  /* no empty mailbox */

    uint32_t dlc = f->dlc > 8u ? 8u : f->dlc;
    CAN_TDTxR(mb) = dlc;
    CAN_TDLxR(mb) = pack_data_lo(f->data);
    CAN_TDHxR(mb) = pack_data_hi(f->data);
    uint32_t ti = f->ide ? ((f->id & 0x1FFFFFFFu) << 3) | TI_IDE
                         : ((f->id & 0x7FFu) << 21);
    CAN_TIxR(mb) = ti | TI_TXRQ;                     /* request transmit */
    return 0;
}

int can_recv(can_frame_t *f)
{
    if (rx_tail == rx_head) return 0;                /* empty */
    *f = rx_ring[rx_tail];
    rx_tail = (rx_tail + 1u) & RX_RING_MASK;
    return 1;
}

int can_inject(const can_frame_t *f)
{
    /* Bench inject runs in main context; mask RX0 so the ISR cannot race our rx_head write. */
    NVIC_ICER0 = (1u << CAN1_RX0_IRQn);
    uint32_t next = (rx_head + 1u) & RX_RING_MASK;
    int ok = 0;
    if (next != rx_tail) {                           /* drop if ring full (same policy as ISR) */
        can_frame_t *dst = &rx_ring[rx_head];
        dst->id  = f->id;
        dst->ide = f->ide;
        dst->dlc = f->dlc > 8u ? 8u : f->dlc;
        for (uint32_t i = 0; i < 8u; i++)
            dst->data[i] = f->data[i];
        rx_head = next;
        ok = 1;
    }
    NVIC_ISER0 = (1u << CAN1_RX0_IRQn);
    return ok;
}

void can_service(void)
{
    /* Auto bus-off recovery is disabled in the stock MCR (ABOM=0); recover by cycling
     * init mode if the controller went bus-off. Harmless when healthy. */
    if (CAN_ESR & ESR_BOFF) {
        CAN_MCR |= MCR_INRQ;
        while (!(CAN_MSR & MSR_INAK)) { }
        CAN_MCR &= ~MCR_INRQ;
        while (CAN_MSR & MSR_INAK) { }
    }
}
