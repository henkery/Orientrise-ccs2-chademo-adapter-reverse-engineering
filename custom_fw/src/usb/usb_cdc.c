/* usb_cdc.c — USB CDC revert console + Stage-1 bench console (REPORT §5.15c). See usb_cdc.h.
 *
 * Services the TinyUSB device CDC link: feeds RX bytes to the framing parser (cdc_proto), buffers
 * streamed UPG bytes into 256-byte pages and writes them to the SPI update pool (revert_stream_write),
 * and on the final byte validates + commits the xPAI descriptor (revert_stream_finish) then resets into
 * the boot. Command responses go back over CDC TX. The UPG is never buffered whole in RAM (~595 KB).
 *
 * Stage-1 bench (all INERT — measurement/communication only, NO power-stage drive):
 *   MEAS / CAN / NET / STM  -> read-only readback of the measurement + protocol layers (RDP:1 blocks
 *                              SWD reads, so the CDC console is the host observability path).
 *   INJC <id> <dlc> <bytes> -> push a CAN frame into the RX ring (can_inject) -> chademo_rx_process.
 *   INJE <n>                -> stream n raw Ethernet bytes -> v2g_net_rx_ethernet (the live RX hook).
 * The upload SINK (cdc_proto_upload_sink) routes UPLOAD_BYTE data to SPI staging (REVERT) or the
 * Ethernet RX injection buffer (ETH).
 */
#include "usb_cdc.h"
#include "cdc_proto.h"
#include "revert_stage.h"
#include "tusb.h"
#include "can.h"
#include "cp.h"
#include "cp_capture.h"
#include "cp_adc.h"
#include "hv.h"
#include "adc.h"
#include "chademo.h"
#include "v2g_net.h"
#include "charge_stm.h"
#include "tick.h"

static uint8_t  page[256];
static uint32_t page_fill;

/* Ethernet RX-injection buffer (INJE sink). A single Ethernet frame <= 1514 B; 1536 leaves headroom.
 * Larger uploads are consumed but flagged overflow (never fed to the stack). */
#define ETH_BUF_SIZE 1536u
static uint8_t  eth_buf[ETH_BUF_SIZE];
static uint32_t eth_fill;
static int      eth_overflow;

static void cdc_send(const char *s)
{
    uint32_t len = 0;
    while (s[len])
        len++;
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = tud_cdc_n_write(0, (const uint8_t *)s + off, len - off);
        tud_cdc_n_write_flush(0);
        off += n;
        if (n == 0)
            tud_task();                   /* TX fifo full: let the stack drain it */
    }
}

/* ---- tiny freestanding formatter (no libc printf): build a readback line into buf ---- */
static uint32_t fmt_s(char *b, uint32_t p, const char *s)
{
    while (*s)
        b[p++] = *s++;
    return p;
}
static uint32_t fmt_u32(char *b, uint32_t p, uint32_t v)
{
    char tmp[10];
    uint32_t n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    } while (v);
    while (n)
        b[p++] = tmp[--n];
    return p;
}
static uint32_t fmt_i32(char *b, uint32_t p, int32_t v)
{
    if (v < 0) {
        b[p++] = '-';
        v = -v;
    }
    return fmt_u32(b, p, (uint32_t)v);
}
static uint32_t fmt_hex8(char *b, uint32_t p, uint8_t v)
{
    static const char h[] = "0123456789ABCDEF";
    b[p++] = h[(v >> 4) & 0xFu];
    b[p++] = h[v & 0xFu];
    return p;
}
static uint32_t fmt_hex16(char *b, uint32_t p, uint16_t v)
{
    p = fmt_hex8(b, p, (uint8_t)(v >> 8));
    return fmt_hex8(b, p, (uint8_t)v);
}

/* ---- read-only measurement readback (pure getters; no side effects) ---- */
static void do_meas(void)
{
    char b[256];
    uint32_t p = 0;
    const cp_t *cp = cp_get();
    uint32_t pp_raw  = cp_adc_pp_raw();
    uint32_t cpd_raw = cp_adc_cpd_raw();
    p = fmt_s(b, p, "HV ");
    p = fmt_i32(b, p, hv_get_outvol());
    b[p++] = ' ';
    p = fmt_i32(b, p, hv_get_raw());
    b[p++] = ' ';
    p = fmt_u32(b, p, (uint32_t)(hv_cal_valid() ? 1 : 0));
    p = fmt_s(b, p, " HVRAW ");
    p = fmt_i32(b, p, adc_get_live_raw());   /* live ADC counts — observable even without cal */
    p = fmt_s(b, p, " CP ");
    p = fmt_u32(b, p, cp_capture_duty());
    b[p++] = ' ';
    p = fmt_u32(b, p, cp_capture_period());
    b[p++] = ' ';
    p = fmt_u32(b, p, cp_capture_update_count());
    p = fmt_s(b, p, " PP ");
    p = fmt_u32(b, p, cp_adc_pp_mv(pp_raw));
    b[p++] = ' ';
    p = fmt_u32(b, p, pp_raw);
    p = fmt_s(b, p, " CPD ");
    p = fmt_u32(b, p, cp_adc_cpd_mv(cpd_raw));
    b[p++] = ' ';
    p = fmt_u32(b, p, cpd_raw);
    p = fmt_s(b, p, " BAT ");
    p = fmt_u32(b, p, cp_adc_bat_mv(cp_adc_bat_raw()));
    p = fmt_s(b, p, " DL ");
    p = fmt_u32(b, p, cp_adc_d_link());
    p = fmt_s(b, p, " PD11 ");
    p = fmt_u32(b, p, cp_adc_pd11());
    p = fmt_s(b, p, " PLUG ");
    p = fmt_u32(b, p, cp_plug_in());
    p = fmt_s(b, p, " ST ");
    b[p++] = (char)cp->cp_state;
    p = fmt_s(b, p, "\r\n");
    b[p] = '\0';
    cdc_send(b);
}

static void do_can(void)
{
    char b[256];
    uint32_t p = 0;
    const chademo_vehicle_t *v = chademo_vehicle();
    p = fmt_s(b, p, "H102 ");
    p = fmt_u32(b, p, v->h102_status);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->target_voltage);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->current_request);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->h102_fault4);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->h102_fault5);
    p = fmt_s(b, p, " H101 ");
    p = fmt_u32(b, p, v->h101_b0);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->h101_b1);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->h101_w2);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->h101_w4);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->h101_b6);
    b[p++] = ' ';
    p = fmt_u32(b, p, v->h101_b7);
    p = fmt_s(b, p, " H100 ");
    for (uint32_t i = 0; i < 8u; i++)
        p = fmt_hex8(b, p, v->h100_raw[i]);
    p = fmt_s(b, p, " SEEN ");
    p = fmt_u32(b, p, v->h100_seen);
    p = fmt_u32(b, p, v->h101_seen);
    p = fmt_u32(b, p, v->h102_seen);
    p = fmt_s(b, p, " FRESH ");
    p = fmt_u32(b, p, (uint32_t)(chademo_bus_fresh(tick_get()) ? 1 : 0));
    p = fmt_s(b, p, "\r\n");
    b[p] = '\0';
    cdc_send(b);
}

static void do_net(void)
{
    char b[256];
    uint32_t p = 0;
    const v2g_net_t *n = v2g_net_get();
    p = fmt_s(b, p, "ST ");
    p = fmt_u32(b, p, n->state);
    p = fmt_s(b, p, " MODE ");
    p = fmt_u32(b, p, n->mode);
    p = fmt_s(b, p, " TLS ");
    p = fmt_u32(b, p, n->use_tls);
    p = fmt_s(b, p, " RX ");
    p = fmt_u32(b, p, n->rx_frames);
    p = fmt_s(b, p, " TX ");
    p = fmt_u32(b, p, n->tx_frames);
    p = fmt_s(b, p, " SPORT ");
    p = fmt_u32(b, p, n->secc_port);
    p = fmt_s(b, p, " LIP ");
    for (uint32_t i = 0; i < 16u; i++)
        p = fmt_hex8(b, p, n->local_ip[i]);
    p = fmt_s(b, p, "\r\n");
    b[p] = '\0';
    cdc_send(b);
}

static void do_stm(void)
{
    char b[128];
    uint32_t p = 0;
    p = fmt_s(b, p, "ST ");
    p = fmt_u32(b, p, charge_stm_state());
    p = fmt_s(b, p, " IL ");
    p = fmt_hex8(b, p, charge_stm_interlock());
    p = fmt_s(b, p, " ENG ");
    p = fmt_u32(b, p, charge_stm_engage_result());
    p = fmt_s(b, p, " ACT ");
    p = fmt_u32(b, p, charge_stm_action());
    p = fmt_s(b, p, " CNT ");
    p = fmt_u32(b, p, charge_stm_phase_cnt());
    p = fmt_s(b, p, "\r\n");
    b[p] = '\0';
    cdc_send(b);
}

static void do_injc(const cdc_proto_result_t *r)
{
    can_frame_t f;
    f.id  = r->inj_id;
    f.ide = 0;
    f.dlc = r->inj_dlc;
    for (uint32_t i = 0; i < 8u; i++)
        f.data[i] = r->inj_data[i];
    if (can_inject(&f))
        cdc_send("OK INJC\r\n");
    else
        cdc_send("ERR INJC full\r\n");
}

static void page_reset(void)
{
    page_fill = 0;
}

/* Flush the buffered upload page to the SPI pool. Returns 0 ok, -1 fail. */
static int page_flush(void)
{
    if (page_fill == 0)
        return 0;
    int rc = revert_stream_write(page, page_fill);
    page_fill = 0;
    return rc;
}

static void abort_upload(const char *msg)
{
    cdc_proto_init();                     /* leave UPLOAD mode, back to CMD */
    page_reset();
    eth_fill = 0;
    eth_overflow = 0;
    cdc_send(msg);
}

void usb_cdc_init(void)
{
    cdc_proto_init();
    page_reset();
    eth_fill = 0;
    eth_overflow = 0;
}

void usb_cdc_task(void)
{
    tud_task();                           /* TinyUSB device stack */

    if (!tud_cdc_n_connected(0))
        return;

    uint8_t rx[64];
    while (tud_cdc_n_available(0)) {
        uint32_t n = tud_cdc_n_read(0, rx, sizeof rx);
        if (n == 0)
            break;
        for (uint32_t i = 0; i < n; i++) {
            cdc_proto_result_t r;
            cdc_proto_feed(rx[i], &r);
            switch (r.event) {
            case CDC_PROTO_REVERT:
                page_reset();
                if (revert_stream_begin(r.filesize) == 0)
                    cdc_send("READY\r\n");
                else
                    abort_upload("ERR begin\r\n");
                break;

            case CDC_PROTO_INJE:
                eth_fill = 0;
                eth_overflow = 0;
                cdc_send("READY\r\n");
                break;

            case CDC_PROTO_UPLOAD_BYTE:
                if (cdc_proto_upload_sink() == CDC_SINK_ETH) {
                    if (eth_fill < ETH_BUF_SIZE)
                        eth_buf[eth_fill++] = r.byte;
                    else
                        eth_overflow = 1;
                    if (r.last) {
                        if (eth_overflow) {
                            cdc_send("ERR INJE overflow\r\n");
                        } else {
                            /* same timebase as the live RX path (ccs2.c: tick_get()*10 = ms) */
                            v2g_net_rx_ethernet(eth_buf, (uint16_t)eth_fill, tick_get() * 10u);
                            cdc_send("OK INJE\r\n");
                        }
                        eth_fill = 0;
                        eth_overflow = 0;
                    }
                } else {
                    page[page_fill++] = r.byte;
                    if (page_fill == sizeof page) {
                        if (page_flush() != 0) {
                            abort_upload("ERR write\r\n");
                            break;
                        }
                    }
                    if (r.last) {
                        if (page_flush() != 0) {
                            abort_upload("ERR write\r\n");
                        } else if (revert_stream_finish() == 0) {
                            cdc_send("OK reverting\r\n");
                            revert_trigger_reset();   /* boot installs stock; does not return */
                        } else {
                            abort_upload("ERR stage\r\n");
                        }
                    }
                }
                break;

            case CDC_PROTO_INJC:
                do_injc(&r);
                break;

            case CDC_PROTO_MEAS:
                do_meas();
                break;

            case CDC_PROTO_CAN:
                do_can();
                break;

            case CDC_PROTO_NET:
                do_net();
                break;

            case CDC_PROTO_STM:
                do_stm();
                break;

            case CDC_PROTO_PING:
                cdc_send("PONG\r\n");
                break;

            case CDC_PROTO_STATUS:
                cdc_send(cdc_proto_in_upload() ? "MODE UPLOAD\r\n" : "MODE CMD\r\n");
                break;

            case CDC_PROTO_HELP:
                cdc_send("CMDS: PING STATUS HELP ABORT REVERT <n> MEAS CAN NET STM "
                         "INJC <id> <dlc> <bytes> INJE <n>\r\n");
                break;

            case CDC_PROTO_ABORT:
                abort_upload("ABORTED\r\n");
                break;

            case CDC_PROTO_UNKNOWN:
                cdc_send("ERR unknown\r\n");
                break;

            case CDC_PROTO_LINE_OVERFLOW:
                cdc_send("ERR line too long\r\n");
                break;

            case CDC_PROTO_NONE:
            default:
                break;
            }
        }
    }
}