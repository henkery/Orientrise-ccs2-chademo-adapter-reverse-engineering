/* chademo.h — CHAdeMO message layer above the CAN1 transport (REPORT §5.8.4/§5.18/§5.21).
 * The adapter is the CHAdeMO charger: RX H100/H101/H102 (vehicle status + request), TX the
 * periodic H108/H109 charger-status messages. Byte->field maps are byte-derived from the C013
 * RX parse (analyze87): frame data byte N, little-endian halfwords.
 *
 *   H102 (0x102): byte0=status, byte1-2=TargetBatteryVoltage(V,LE), byte3=ChargingCurrentRequest(A),
 *                 byte4/byte5=fault bytes.
 *   H101 (0x101): byte0/1=status bytes, byte2-3 & byte4-5=LE halfwords, byte6/7=status bytes.
 *   H100 (0x100): vehicle status (kept raw for the state-machine layer).
 *
 * INERT: parse/build + reporting only. No power-stage GPIO drive; the state machine that acts
 * on these fields (and drives d1/d2/contactors) is a later, GATED layer. H108/H109 are sent
 * with a standby status + zero output until the measurement + state-machine layers exist.
 */
#ifndef CHADEMO_H
#define CHADEMO_H
#include <stdint.h>

#define CHADEMO_ID_H100  0x100u
#define CHADEMO_ID_H101  0x101u
#define CHADEMO_ID_H102  0x102u
#define CHADEMO_ID_H108  0x108u
#define CHADEMO_ID_H109  0x109u

/* RX watchdogs in 100 Hz ticks (10 ms): per-message 1 s = 100 ticks (§5.8.5). */
#define CHADEMO_MSG_WD_TICKS   100u
/* Whole-bus loss watchdog: C013 = 1525 ticks (15.25 s, §5.21). */
#define CHADEMO_BUS_WD_TICKS   1525u
/* H108/H109 periodic TX every 10 ticks = 100 ms (§5.18 modulo-10 schedule). */
#define CHADEMO_TX_PERIOD_TICKS 10u

typedef struct {
    /* H100 vehicle status — raw bytes (interpreted by the state-machine layer). */
    uint8_t  h100_raw[8];
    /* H101 charging-enable / contactor (byte-derived field slots). */
    uint8_t  h101_b0, h101_b1;
    uint16_t h101_w2, h101_w4;
    uint8_t  h101_b6, h101_b7;
    /* H102 charging request (confirmed C013 parse). */
    uint8_t  h102_status;          /* byte0 */
    uint16_t target_voltage;       /* byte1-2, V, LE */
    uint8_t  current_request;      /* byte3, A */
    uint8_t  h102_fault4;          /* byte4 */
    uint8_t  h102_fault5;          /* byte5 */
    /* reception timestamps (100 Hz tick) + seen flags for the watchdogs. */
    uint32_t last_h100, last_h101, last_h102;
    uint8_t  h100_seen, h101_seen, h102_seen;
} chademo_vehicle_t;

void chademo_init(void);
void chademo_rx_process(uint32_t tick);   /* drain CAN RX ring, parse H100/H101/H102 */
void chademo_tx_periodic(uint32_t tick);  /* every 10 ticks: build + send H108/H109 (standby) */
/* Set the measured output voltage (volts) reported in H108 byte1-2 (stock 450 clamp). The
 * status stays standby (0) — this is measurement reporting only, no charge enable. Lets a
 * CAN bench read get_hv()/10 without SWD. Negative/invalid -> 0. */
void chademo_set_outvol(int32_t volts);
const chademo_vehicle_t *chademo_vehicle(void);
/* 1 if any vehicle message received within the whole-bus watchdog window. */
int  chademo_bus_fresh(uint32_t tick);

#endif /* CHADEMO_H */
