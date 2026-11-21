/* sdp.h — SECC Discovery Protocol + V2GTP + appHandshake (REPORT §5.9, Agent C / analyze92).
 *
 * Faithful INERT replica of the C013 SDP/V2G state machine (0x08020468, ctx 0x20000BBC) that
 * discovers the EVSE's SECC (IPv6 address + TCP port) and negotiates the application protocol.
 *
 *   security select 0x080204FA : req security = 0x10 (TLS) iff (RootCertCount & 0xFF)==0 else 0x00
 *                                (accessor 0x08051AAC reads 0x20018A64 low24 + 0x20018A68 high8;
 *                                 the test is LOW-BYTE-ONLY tst #0xff)
 *   SDP req build   0x0802064A : V2GTP 0x9000, payload {security, transport=0} ->
 *                                wire 01 FE 90 00 00 00 00 02 <SEC> 00 (10 bytes)
 *   dest template   0x080209B0 : ff02::1 (IPv6 link-local all-nodes multicast), type 6, port 15118
 *   retry           0x0802059E : 50 count, 500 ms initial then 250 ms after each send
 *   SDP res (28B)              : 01 FE 90 01 00 00 00 14 + SECC IPv6[16]@+8 + port u16 BE@+0x18
 *                                + security@+0x1a + transport@+0x1b
 *   res validator   0x080212E0 : type 0x9001, len 28, transport 0, security in {0,0x10}, IP!=0, port!=0
 *   TLS decision    0x080207BC : TLS iff SECC security byte != 0
 *   appHandshake    0x08033B4E : DIN urn:din:70121:2012:MsgDef Priority1/SchemaID1 (preferred),
 *                                ISO urn:iso:15118:2:2013:MsgDef Priority2/SchemaID2; both Major2/Minor0
 *   set-protocol    0x08023A8C : selected protocol @0x200137CC (1=DIN, 2=ISO)
 *
 * INERT: pure message build/parse/validate + protocol selection host-tested (test_sdp.c). The live
 * UDP/TCP/IPv6 + mbedTLS transport is a large stack NOT present in the bare-metal app — TX is behind
 * a hook (sdp_set_send) and the SM is driven by injected RX (sdp_rx) + timers (sdp_step); until an
 * IP stack is wired the network layer stays GATED. Communication only — no power-stage GPIO.
 */
#ifndef SDP_H
#define SDP_H
#include <stdint.h>

#define SDP_PORT            15118u   /* 0x3B0E SECC discovery port           */
#define SDP_RETRY_COUNT     50u      /* 0x32                                 */
#define SDP_T_INITIAL_MS    500u     /* 0x1F4 first timeout                  */
#define SDP_T_SUBSEQ_MS     250u     /* 0xFA subsequent                      */
#define SDP_SECURITY_TLS    0x10u
#define SDP_SECURITY_NONE   0x00u
#define SDP_RES_LEN         28u      /* 0x1C                                 */
#define SDP_IP_TYPE_IPV6    6u

#define SDP_PROTO_DIN       1u       /* SchemaID 1 -> DIN70121 (preferred)   */
#define SDP_PROTO_ISO       2u       /* SchemaID 2 -> ISO15118-2             */

typedef enum {
    SDP_ST_IDLE = 0,
    SDP_ST_REQ,          /* build + send SDP request (UDP multicast)         */
    SDP_ST_WAIT_RES,     /* wait SDP response, retry on timeout              */
    SDP_ST_TCP_CONNECT,  /* SECC found; open TCP (TLS iff security!=0)       */
    SDP_ST_DONE,         /* SECC address + port + protocol resolved          */
    SDP_ST_FAILED
} sdp_state_t;

typedef struct {
    uint8_t  state;            /* sdp_state_t                              */
    uint8_t  req_security;     /* 0x10 TLS / 0x00 none                     */
    uint8_t  secc_ip[16];      /* SECC IPv6 (network order)                */
    uint16_t secc_port;        /* SECC TCP port (host order)               */
    uint8_t  secc_security;    /* SECC security byte                       */
    uint8_t  use_tls;          /* 1 iff secc_security != 0                 */
    uint8_t  selected_protocol;/* SDP_PROTO_DIN / SDP_PROTO_ISO            */
    uint8_t  retries;          /* remaining retries                        */
    uint16_t timer_ms;         /* current retry timeout                    */
    uint32_t last_send;        /* last-send tick                           */
} sdp_t;

/* TX hook: send a V2GTP frame over UDP to ff02::1:15118 (NULL = inert, frame recorded only). */
typedef void (*sdp_send_fn)(const uint8_t *frame, uint16_t len);
void sdp_set_send(sdp_send_fn fn);

/* Pure helpers (byte-exact, host-testable). */
/* 0x080204FA: (root_cert_count & 0xFF)==0 -> 0x10 (TLS) else 0x00. Low-byte-only test. */
uint8_t sdp_security_select(uint32_t root_cert_count);
/* Build the SDP request: V2GTP 0x9000 + payload {security,0}. Returns 10. */
uint16_t sdp_build_req(uint8_t *buf, uint8_t security);
/* 0x080212E0: validate a 28-byte SDP response. Returns 1 if valid. */
int sdp_res_valid(const uint8_t *buf, uint16_t len);
/* Parse a validated SDP response into SECC ip[16]/port/security. */
void sdp_res_parse(const uint8_t *buf, uint8_t *ip, uint16_t *port, uint8_t *security);
/* appHandshake response: SchemaID 1->DIN(1), 2->ISO(2), else 0 (shutdown). */
uint8_t sdp_select_protocol(uint8_t schema_id);

void sdp_init(uint32_t root_cert_count);
void sdp_step(uint32_t tick);
/* Inject a received SDP response (or appHandshake EXI via the session layer). */
void sdp_rx(const uint8_t *buf, uint16_t len);
const sdp_t *sdp_get(void);

#endif /* SDP_H */