/* test_ccs2.c — host unit test for the CCS2 EVCC controller glue (custom_fw/src/ccs2.c, §5.9).
 * Tests the confirmed integration: current_ctrl EVSE-measurement fill, CurrentDemand actuation,
 * DIN session flag setters -> charge_stm EVSE outputs, CurrentDemandRes decode. QCA7005 stubbed.
 * Build + run (links exi.c + din_session.c + v2g_net.c — the autonomous session SM + live transport
 * carriage wired into ccs2_step/ccs2_rx):
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_ccs2 test_ccs2.c \
 *       src/ccs2.c src/slac.c src/sdp.c src/cp.c src/din70121.c src/exi.c src/din_session.c \
 *       src/v2gtp.c src/v2g_net.c && ./test_ccs2'
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ccs2.h"
#include "din70121.h"
#include "qca7005.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

/* QCA7005 stubs */
static const uint8_t mac[6] = { 0xFE, 0xFF, 0xFE, 0xFF, 0x00, 0x01 };
int qca7005_frame_send(const uint8_t *f, uint16_t len) { (void)f; (void)len; return 0; }
const uint8_t *qca7005_mac(void) { return mac; }
/* tick stub: ccs2_rx timestamps the IPv6 RX path via tick_get()*10 (ms). */
uint32_t tick_get(void) { return 0; }
/* spi4 stub: ca_store (linked via ccs2) defaults to spi4_read; no ext flash on the host. */
int spi4_read(uint32_t addr, uint8_t *dst, uint32_t len) { (void)addr; (void)dst; (void)len; return -1; }

static void st16(uint8_t *p, uint16_t v) { p[0] = v & 0xFF; p[1] = v >> 8; }

int main(void)
{
    ccs2_init();
    CHECK(ccs2_state() == CCS2_IDLE, "init state IDLE");

    /* --- current_ctrl EVSE-measurement fill from DIN meas --- */
    din_meas_t *m = din70121_meas_mut();
    m->evse_max_current = 200;     m->evse_max_current_f = 3;       /* 200 A cap */
    m->evse_present_current = 150; m->evse_present_current_f = 3;   /* 150 A avail */
    m->evse_max_voltage = 500;     m->evse_max_voltage_f = 3;       /* 500 V limit */
    current_ctrl_inputs_t ci;
    memset(&ci, 0, sizeof ci);
    ccs2_fill_current_ctrl(&ci);
    CHECK(ci.evse_max_raw == 200 && ci.evse_max_factor == 3, "fill max raw/factor 200/3");
    CHECK(ci.evse_avail_raw == 150 && ci.evse_avail_factor == 3, "fill avail raw/factor 150/3");
    CHECK(ci.voltage_limit == 500, "fill voltage limit = scaled EVSE max V 500");

    /* --- CurrentDemand actuation: setpoint -> EV targets -> EXI image --- */
    uint8_t exi[DIN_CDQ_TX_LEN];
    uint16_t n = ccs2_demand(120, 400, exi);
    CHECK(n == DIN_CDQ_TX_LEN, "demand returns 108");
    CHECK(exi[DIN_CDQ_EXI_TARGET_I] == 120 && exi[DIN_CDQ_EXI_TARGET_I + 1] == 0, "demand targetI 120");
    CHECK(exi[DIN_CDQ_EXI_TARGET_V] == (400 & 0xFF) && exi[DIN_CDQ_EXI_TARGET_V + 1] == (400 >> 8),
          "demand targetV 400");
    CHECK(exi[DIN_CDQ_EXI_TARGET_I_F] == 0 && exi[DIN_CDQ_EXI_TARGET_V_F] == 0, "demand wire factors 0");
    CHECK(din70121_meas()->ev_target_current == 120, "demand stored EV target current");

    /* --- DIN session flag setters -> charge_stm EVSE outputs --- */
    ccs2_session_start();
    CHECK(ccs2_state() == CCS2_SESSION, "session_start -> SESSION");
    ccs2_cablecheck_done(4);
    ccs2_chgparam_done();
    ccs2_precharge_ready();
    ccs2_ev_contactor_closed();
    ccs2_precharge_relay_closed();
    const ccs2_evse_t *e = ccs2_evse();
    CHECK(e->cablecheck_fin == 1 && e->isolation == 4, "cablecheck done + isolation 4");
    CHECK(e->chgparam_ok == 1, "chgparam ok");
    CHECK(e->precharge_flag == 1, "precharge flag 1");
    CHECK(e->ev_contactor == 1 && e->precharge_relay == 1, "contactor + relay feedback");
    /* step advances SESSION -> CURRENT_DEMAND once flags set */
    ccs2_step(0);
    CHECK(ccs2_state() == CCS2_CURRENT_DEMAND, "flags set -> CURRENT_DEMAND");

    /* --- CurrentDemandRes decode updates meas (EVSE present/max) --- */
    uint8_t cdr[128]; memset(cdr, 0, sizeof cdr);
    st16(cdr + DIN_CDR_EXI_PRESENT_I, 90);  cdr[DIN_CDR_EXI_PRESENT_I_F] = 0;
    st16(cdr + DIN_CDR_EXI_PRESENT_V, 380); cdr[DIN_CDR_EXI_PRESENT_V_F] = 0;
    st16(cdr + DIN_CDR_EXI_MAX_I, 180);     cdr[DIN_CDR_EXI_MAX_I_F] = 0; cdr[0x2A] = 1;
    ccs2_currentdemand_res(cdr);
    CHECK(din70121_meas()->evse_present_current == 90, "CD res presentI 90");
    CHECK(din70121_meas()->evse_max_current == 180, "CD res maxI 180");
    ccs2_fill_current_ctrl(&ci);
    CHECK(ci.evse_avail_raw == 90 && ci.evse_max_raw == 180, "fill reflects CD res 90/180");

    /* --- session stop clears flags --- */
    ccs2_session_stop();
    CHECK(ccs2_state() == CCS2_STOP, "session_stop -> STOP");
    CHECK(ccs2_evse()->cablecheck_fin == 0 && ccs2_evse()->precharge_flag == 0, "stop clears flags");

    /* --- RX dispatch: MME EtherType 0x88E1 routed to SLAC (no crash, len guard) --- */
    uint8_t frame[64]; memset(frame, 0, sizeof frame);
    frame[12] = 0x88; frame[13] = 0xE1;
    ccs2_rx(frame, 64);   /* SLAC idle ignores; just verify dispatch path runs */
    ccs2_rx(frame, 4);    /* short-frame guard */
    CHECK(1, "RX dispatch MME + short guard runs");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}