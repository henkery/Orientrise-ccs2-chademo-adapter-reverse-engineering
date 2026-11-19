/* chademo.c — CHAdeMO message parse/build (REPORT §5.8.4/§5.18/§5.21, analyze87).
 * RX byte->field maps are byte-derived from the C013 parse (frame buffer has a 4-byte ID
 * header; CAN data byte N is the Nth payload byte; halfwords little-endian via helper
 * 0x08050976 = b0|b1<<8). H108/H109 TX packing follows §5.18 (/1000 scaling, 450 clamp,
 * H109 byte5 low-6-bit reversal) — here sent with standby status + zero output because the
 * measurement (get_hv) and state-machine layers do not exist yet. INERT: no power-stage drive.
 */
#include "chademo.h"
#include "can.h"

static chademo_vehicle_t veh;
static uint32_t last_tx_tick;
static uint16_t report_outvol;            /* measured output voltage (V) for H108 byte1-2 */

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

void chademo_init(void)
{
    /* zero the whole struct (timestamps/seen flags cleared) */
    uint8_t *p = (uint8_t *)&veh;
    for (unsigned i = 0; i < sizeof(veh); i++) p[i] = 0;
    last_tx_tick = 0;
    report_outvol = 0;
}

void chademo_set_outvol(int32_t volts)
{
    report_outvol = (volts > 0) ? (uint16_t)volts : 0u;   /* 450 clamp applied in send_h108 */
}

const chademo_vehicle_t *chademo_vehicle(void)
{
    return &veh;
}

void chademo_rx_process(uint32_t tick)
{
    can_frame_t f;
    while (can_recv(&f)) {
        if (f.ide) continue;                 /* CHAdeMO is 11-bit standard; GB/T extended handled later */
        const uint8_t *d = f.data;
        switch (f.id) {
        case CHADEMO_ID_H100:
            for (int i = 0; i < 8; i++) veh.h100_raw[i] = d[i];
            veh.last_h100 = tick; veh.h100_seen = 1;
            break;
        case CHADEMO_ID_H101:
            veh.h101_b0 = d[0]; veh.h101_b1 = d[1];
            veh.h101_w2 = rd_le16(&d[2]);
            veh.h101_w4 = rd_le16(&d[4]);
            veh.h101_b6 = d[6]; veh.h101_b7 = d[7];
            veh.last_h101 = tick; veh.h101_seen = 1;
            break;
        case CHADEMO_ID_H102:
            veh.h102_status     = d[0];
            veh.target_voltage  = rd_le16(&d[1]);
            veh.current_request = d[3];
            veh.h102_fault4     = d[4];
            veh.h102_fault5     = d[5];
            veh.last_h102 = tick; veh.h102_seen = 1;
            break;
        default:
            break;
        }
    }
}

/* H108 (0x108) charger output status: byte0=status, byte1-2=output value (LE, /1000-scaled,
 * clamped to 450 in stock), byte3..7=status/measurements. Standby: status=0, output=0. */
static void send_h108(uint8_t status, uint16_t out_value)
{
    can_frame_t f;
    f.id = CHADEMO_ID_H108; f.ide = 0; f.dlc = 8;
    if (out_value > 450u) out_value = 450u;          /* stock 450 clamp (§5.18) */
    f.data[0] = status;
    f.data[1] = (uint8_t)out_value;
    f.data[2] = (uint8_t)(out_value >> 8);
    f.data[3] = 0; f.data[4] = 0; f.data[5] = 0; f.data[6] = 0; f.data[7] = 0;
    can_send(&f);
}

/* H109 (0x109) charger status / remaining time: byte0=status, byte1-2=value (LE), byte3=value,
 * byte4, byte5=low-6-bits bit-reversed on the wire, byte6-7. Standby: status=0, values=0. */
static void send_h109(uint8_t status, uint16_t value)
{
    can_frame_t f;
    f.id = CHADEMO_ID_H109; f.ide = 0; f.dlc = 8;
    f.data[0] = status;
    f.data[1] = (uint8_t)value;
    f.data[2] = (uint8_t)(value >> 8);
    f.data[3] = 0; f.data[4] = 0;
    f.data[5] = 0;                                  /* low-6-bit reversal of 0 = 0 */
    f.data[6] = 0; f.data[7] = 0;
    can_send(&f);
}

void chademo_tx_periodic(uint32_t tick)
{
    if ((tick - last_tx_tick) < CHADEMO_TX_PERIOD_TICKS) return;
    last_tx_tick = tick;
    /* Standby status (0 = not charging) — no charge enable. H108 byte1-2 now carries the
     * measured output voltage (get_hv()/10, 450-clamped) for CAN-bench validation; H109 stays
     * zero. The stock builds set status 1 (H108) / 3 (H109) only in CurrentDemand. */
    send_h108(0, report_outvol);
    send_h109(0, 0);
}

int chademo_bus_fresh(uint32_t tick)
{
    if (veh.h100_seen && (tick - veh.last_h100) <= CHADEMO_BUS_WD_TICKS) return 1;
    if (veh.h101_seen && (tick - veh.last_h101) <= CHADEMO_BUS_WD_TICKS) return 1;
    if (veh.h102_seen && (tick - veh.last_h102) <= CHADEMO_BUS_WD_TICKS) return 1;
    return 0;
}
