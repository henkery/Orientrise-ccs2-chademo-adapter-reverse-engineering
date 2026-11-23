/* can.h — bxCAN CAN1 transport for the custom adapter app (REPORT §5.8.2, analyze79).
 * CAN1-only board: PD0 RX / PD1 TX (AF9), 500 kbit/s CHAdeMO (BTR 0x00270006 @ APB1 42 MHz).
 * Interrupt-driven RX (FIFO0 pending -> CAN1_RX0_IRQHandler drains into a ring buffer);
 * polled TX (3 mailboxes). Protocol-agnostic: the CHAdeMO parse/build sits above this.
 * INERT: this is communication only — no power-stage GPIO drive.
 */
#ifndef CAN_H
#define CAN_H
#include <stdint.h>

#define CAN_BTR_500K  0x00270006u   /* BRP=6(psc7) BS1=8 BS2=3 SJW=1 -> 42MHz/7/12 = 500k, 75% SP */

typedef struct {
    uint32_t id;        /* 11-bit standard ID (or 29-bit extended when ide=1) */
    uint8_t  ide;       /* 0 = standard, 1 = extended */
    uint8_t  dlc;       /* 0..8 */
    uint8_t  data[8];
} can_frame_t;

void can_init(void);                 /* GPIO + CAN1 init + filters + NVIC RX0; call before enable_irq */
int  can_send(const can_frame_t *f); /* queue into an empty TX mailbox; 0 ok, -1 no mailbox free */
int  can_recv(can_frame_t *f);       /* pop one RX frame from the ring; 1 ok, 0 empty */
void can_service(void);              /* periodic bus-off recovery / error check (call from 100 Hz loop) */
/* Bench RX injection: push a frame into the RX ring exactly as the ISR would (no bus traffic needed).
 * Masks the RX0 IRQ around the push so it cannot race the ISR's rx_head write. Returns 1 ok, 0 ring
 * full. INERT: feeds the CHAdeMO parse path only — no power-stage drive. Stage-1 fidelity bench. */
int  can_inject(const can_frame_t *f);

#endif /* CAN_H */
