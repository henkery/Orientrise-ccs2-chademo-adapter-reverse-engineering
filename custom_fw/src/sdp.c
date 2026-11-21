/* sdp.c — SECC Discovery Protocol + V2GTP + appHandshake (REPORT §5.9, Agent C / analyze92).
 * Faithful INERT replica of the C013 SDP/V2G state machine. Pure message logic host-tested
 * (test_sdp.c); the live UDP/TCP/IPv6+TLS transport is behind a hook (gated). No power GPIO.
 */
#include "sdp.h"
#include "v2gtp.h"

static sdp_t sdp;
static sdp_send_fn send_hook;
static uint8_t req_buf[16];

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }
static void cp(uint8_t *d, const uint8_t *s, uint16_t n) { for (uint16_t i = 0; i < n; i++) d[i] = s[i]; }

uint8_t sdp_security_select(uint32_t root_cert_count)
{
    /* 0x080204FA: bl 0x8051aac ; tst.w r0,#0xff ; beq -> 0x10 ; else 0x00. LOW-BYTE-ONLY.
     * Wire encoding 0x00=TLS / 0x10=No-TLS: no PnC root certs (count==0) -> request No-TLS (0x10);
     * has root certs -> request TLS (0x00). (The prior "0x10=TLS" label was inverted.) */
    return ((root_cert_count & 0xFFu) == 0u) ? SDP_SECURITY_NONE : SDP_SECURITY_TLS;
}

uint16_t sdp_build_req(uint8_t *buf, uint8_t security)
{
    /* 0x0802064A: payload {security, transport=0} @buf[8..9] ; V2GTP type 0x9000, len 2 -> 10. */
    buf[8] = security;
    buf[9] = 0u;   /* transport = TCP */
    return v2gtp_encode(buf, 2u, V2GTP_TYPE_SDP_REQ);
}

int sdp_res_valid(const uint8_t *buf, uint16_t len)
{
    /* 0x080212E0: type 0x9001 ; len 28 ; transport==0 ; security in {0,0x10} ; IP!=0 ; port!=0. */
    uint16_t plen = 0;
    if (v2gtp_parse(buf, len, &plen) != V2GTP_TYPE_SDP_RES) return 0;
    if (len != SDP_RES_LEN) return 0;
    if (buf[0x1b] != 0) return 0;                       /* transport must be TCP */
    if (buf[0x1a] != SDP_SECURITY_NONE && buf[0x1a] != SDP_SECURITY_TLS) return 0;
    int ip_nonzero = 0;
    for (uint16_t i = 8; i < 0x18; i++) if (buf[i] != 0) { ip_nonzero = 1; break; }
    if (!ip_nonzero) return 0;
    uint16_t port = ((uint16_t)buf[0x18] << 8) | buf[0x19];
    if (port == 0) return 0;
    return 1;
}

void sdp_res_parse(const uint8_t *buf, uint8_t *ip, uint16_t *port, uint8_t *security)
{
    /* 0x080205D8: IP[16]@+8 ; port BE@+0x18 (rev16 -> LE) ; security@+0x1a. */
    cp(ip, buf + 8, 16);
    *port = (uint16_t)(((uint16_t)buf[0x18] << 8) | buf[0x19]);
    *security = buf[0x1a];
}

uint8_t sdp_select_protocol(uint8_t schema_id)
{
    /* 0x08032420 / 0x08023A8C: SchemaID 1 -> DIN(1), 2 -> ISO(2), else 0 (goto shutdown). */
    if (schema_id == 1u) return SDP_PROTO_DIN;
    if (schema_id == 2u) return SDP_PROTO_ISO;
    return 0u;
}

void sdp_set_send(sdp_send_fn fn) { send_hook = fn; }

void sdp_init(uint32_t root_cert_count)
{
    z((uint8_t *)&sdp, sizeof sdp);
    sdp.state = SDP_ST_IDLE;
    sdp.req_security = sdp_security_select(root_cert_count);
    sdp.retries = SDP_RETRY_COUNT;
    sdp.timer_ms = SDP_T_INITIAL_MS;
}

void sdp_step(uint32_t tick)
{
    switch (sdp.state) {
    case SDP_ST_IDLE:
        sdp.state = SDP_ST_REQ;
        sdp.last_send = 0;
        /* fallthrough */
    case SDP_ST_REQ: {
        uint16_t n = sdp_build_req(req_buf, sdp.req_security);
        if (send_hook) send_hook(req_buf, n);   /* inert: NULL hook -> recorded only */
        sdp.last_send = tick;
        sdp.timer_ms = SDP_T_SUBSEQ_MS;         /* 250 ms after the first send */
        sdp.state = SDP_ST_WAIT_RES;
        break;
    }
    case SDP_ST_WAIT_RES:
        /* retry on timeout (tick is 10 ms; timer_ms converted to ticks). */
        if ((uint32_t)(tick - sdp.last_send) >= (sdp.timer_ms / 10u)) {
            if (sdp.retries == 0) { sdp.state = SDP_ST_FAILED; break; }
            sdp.retries--;
            sdp.state = SDP_ST_REQ;
        }
        break;
    case SDP_ST_TCP_CONNECT:
        /* TCP open + TLS handshake handled by the (gated) IP/session layer; once connected the
         * appHandshake selects the protocol. Inert replica advances on injected appHandshake res. */
        break;
    case SDP_ST_DONE:
    case SDP_ST_FAILED:
    default:
        break;
    }
}

void sdp_rx(const uint8_t *buf, uint16_t len)
{
    if (sdp.state == SDP_ST_WAIT_RES && sdp_res_valid(buf, len)) {
        sdp_res_parse(buf, sdp.secc_ip, &sdp.secc_port, &sdp.secc_security);
        sdp.use_tls = (sdp.secc_security == 0u) ? 1u : 0u;   /* 0x080207BC: cbz -> TLS (wire 0x00=TLS) */
        sdp.state = SDP_ST_TCP_CONNECT;
    }
}

const sdp_t *sdp_get(void) { return &sdp; }