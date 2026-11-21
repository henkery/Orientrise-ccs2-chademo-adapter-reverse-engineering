/* nd6.h — IPv6 Neighbor Discovery (RFC 4861) neighbor cache + NS/NA/RA (REPORT §5.9, Agent N).
 *
 * Faithful INERT replica of the C013 lwIP nd6 layer that resolves the SECC's link-local IPv6 to
 * an Ethernet MAC so the TCP/TLS transport (v2g_net) can frame unicast packets. Byte-derived from:
 *
 *   RX demux        ethernet_input 0x0809D914 -> ip6_input 0x0809B88E/demux 0x0809BB2C
 *                   (next-header 58=ICMPv6) -> icmp6_input 0x0809B3D0 (134/135/136/137 -> nd6_input
 *                   0x0809C926).
 *   neighbor cache  0x20024524 = 10 x 40 B (0x28) entries {+0 IPv6[16], +0x10 netif ptr,
 *                   +0x14 MAC[6], +0x1C queued-pbuf head, +0x20 state u8, +0x21 is_router u8,
 *                   +0x24 counter u32}; entry = base + idx*40 (new_neighbor 0x0809C368 idx*5*8).
 *   state enum      TBB nd6_tmr 0x0809D030 bytes 37 03 0e 1c 1f 2b ->
 *                   0 UNUSED / 1 INCOMPLETE / 2 REACHABLE / 3 STALE / 4 DELAY / 5 PROBE.
 *   ND6 global      0x20000B70 {+0 cached neighbor idx, +1 cached router idx, +4 reachable_time,
 *                   +8 retransmit_time} — RA-driven (RA reachable/retrans options).
 *   NS receive      0x0809CC84 strb state=4 (DELAY) / 0x0809CC88 counter=5  ** DEVIATION from stock
 *                   lwIP (which sets STALE=3) **; src MAC from SLLA -> entry+0x14; new entry copies
 *                   src IPv6. If target == own address -> send NA (DAD 0x22 / solicited 0x60).
 *   NA receive      0x0809CAE2 state=2 (REACHABLE) / 0x0809CAEE counter=reachable_time; find_neighbor
 *                   by the NA *target* address; TLLA MAC copied only if the Override flag (0x20) set;
 *                   flush_queue 0x0809C8BA.
 *   RA receive      reachable_time (RA+8, ntohl, only if non-zero) / retransmit_time (RA+12, ntohl)
 *                   -> ND6 global; router lifetime -> router-info table 0x200248D0.
 *   NS send         nd6_send_ns 0x0809C520: type 135, code 0, reserved 0, target[16]@+8, SLLA option
 *                   {type 1 @+0x18, len 1 @+0x19, MAC[6] @+0x1A} (len = (hwaddr_len+9)>>3 = 1 unit);
 *                   hop 255; flags bit0 -> solicited-node mcast ff02::1:ffXX:XXXX (word0=0x2ff,
 *                   word2=0x1000000, word3=target[3]|0xff) else unicast target.
 *   NA send         nd6_send_na 0x0809C7BA: type 136, flags byte@+4 = (flags & 0xF0) (R=0x80/S=0x40/
 *                   O=0x20), target[16]@+8, TLLA {type 2, len 1, MAC[6]}; dst flags bit0 -> solicited
 *                   mcast, bit1 -> all-nodes ff02::1, else unicast; DAD reply 0x22 / solicited 0x60.
 *   TX lookup       ethip6_output 0x0809B35C: mcast -> 33:33:dst[12..15]; unicast -> lookup
 *                   0x0809D5D6 (STALE->DELAY/counter5; REACHABLE/DELAY/PROBE -> MAC; else queue + NS).
 *   nd6_tmr         0x0809D012 (1 s tick): REACHABLE counter-=1000 -> STALE@<=1000; DELAY counter--
 *                   -> PROBE@<=1; INCOMPLETE/PROBE probe-count++ -> free@>=3 (if !router) else NS
 *                   (INCOMPLETE mcast flags1 / PROBE unicast flags0); STALE age++.
 *
 * INERT: communication only — drives NO power-stage GPIO. The neighbor cache state machine + the
 * NS/NA/RA wire frames are pure logic, host-unit-tested (test_nd6.c); live TX is behind a hook
 * (nd6_set_send, NULL = inert recorded-only) and RX is injected (nd6_input). The queued-pbuf flush
 * is modelled as a count (real pbuf re-send is the gated live transport). Pre-RA reachable/retrans
 * defaults are the stock lwIP 30000/1000 ms [? not byte-proven before the first RA].
 */
#ifndef ND6_H
#define ND6_H
#include <stdint.h>

#define ND6_CACHE_SIZE        10u    /* 0x20024524 = 10 entries                  */
#define ND6_STATE_UNUSED      0u
#define ND6_STATE_INCOMPLETE  1u
#define ND6_STATE_REACHABLE   2u
#define ND6_STATE_STALE       3u
#define ND6_STATE_DELAY       4u
#define ND6_STATE_PROBE       5u

#define ND6_REACHABLE_TIME_MS 30000u /* [?] pre-RA default (stock lwIP)          */
#define ND6_RETRANS_TIME_MS   1000u  /* [?] pre-RA default (stock lwIP)          */
#define ND6_NS_RECV_COUNTER   5u     /* DEVIATION: NS-receive sets counter=5     */
#define ND6_MAX_PROBES        3u     /* INCOMPLETE/PROBE free at probe-count>=3  */
#define ND6_REACHABLE_TICK_MS 1000u  /* nd6_tmr 1 s tick subtracts 1000          */

/* ICMPv6 type codes (RFC 4861) */
#define ND6_ICMP6_RS          133u
#define ND6_ICMP6_RA          134u
#define ND6_ICMP6_NS          135u
#define ND6_ICMP6_NA          136u
#define ND6_ICMP6_REDIRECT    137u
#define ND6_ICMP6_PTB         2u     /* Packet Too Big (icmp6_input dispatch)    */

/* ND6 option types + NA flag bits */
#define ND6_OPT_SLLA          1u
#define ND6_OPT_TLLA          2u
#define ND6_NA_FLAG_R         0x80u  /* Router                                   */
#define ND6_NA_FLAG_S         0x40u  /* Solicited                                */
#define ND6_NA_FLAG_O         0x20u  /* Override                                 */
#define ND6_NA_DAD            0x22u  /* DAD reply: all-nodes dst (bit1) + O      */
#define ND6_NA_SOLICITED      0x60u  /* solicited reply: unicast dst + S + O     */
#define ND6_NS_FLAG_SOLICITED 0x01u  /* NS send flags bit0 -> solicited mcast dst*/

#define ND6_ICMP6_HDR_LEN     8u     /* type/code/cksum + reserved/flags         */
#define ND6_TARGET_LEN        16u
#define ND6_OPT_MAC_LEN       8u     /* SLLA/TLLA: type1 + len1 + MAC6           */
#define ND6_NS_LEN            32u    /* 8 hdr + 16 target + 8 SLLA               */
#define ND6_NA_LEN            32u    /* 8 hdr + 16 target + 8 TLLA               */

typedef struct {
    uint8_t  ip[16];        /* +0x00 neighbor IPv6 (network order)              */
    uint8_t  mac[6];        /* +0x14 resolved link-layer address                */
    uint8_t  state;         /* +0x20 ND6_STATE_*                                */
    uint8_t  is_router;     /* +0x21                                            */
    uint32_t counter;       /* +0x24 REACHABLE/DELAY: ms/ticks; INCOMPLETE/PROBE/STALE: count */
    uint16_t queued;        /* +0x1C queued-packet count (inert flush model)    */
} nd6_neighbor_t;

typedef struct {
    nd6_neighbor_t cache[ND6_CACHE_SIZE];
    uint32_t reachable_time;   /* ND6 global +4 (RA-driven)                     */
    uint32_t retransmit_time;  /* ND6 global +8 (RA-driven)                     */
    uint8_t  cached_neighbor;  /* ND6 global +0                                 */
    uint8_t  cached_router;    /* ND6 global +1                                 */
    uint8_t  local_ip[16];     /* own link-local IPv6 (DAD target match)        */
    uint8_t  local_mac[6];     /* own MAC (SLLA/TLLA source)                    */
    uint32_t ns_sent;
    uint32_t na_sent;
    uint32_t ra_recv;
    uint32_t flushed;          /* packets released by flush_queue (inert count) */
} nd6_t;

/* TX hook: send a full Ethernet frame (NULL = inert, frame recorded only). */
typedef void (*nd6_send_fn)(const uint8_t *frame, uint16_t len);
void nd6_set_send(nd6_send_fn fn);
void nd6_init(void);
/* Set own link-local IPv6 + MAC (from the QCA7005 PIB MAC / v2g_net link-local). */
void nd6_set_local(const uint8_t ip[16], const uint8_t mac[6]);
const nd6_t *nd6_get(void);

/* ---- pure, host-testable wire helpers (byte-exact, no hardware) ---- */
/* Solicited-node multicast ff02::1:ffXX:XXXX from target (word0=0x2ff, word2=0x1000000,
 * word3=target[3]|0xff). out[16] network order. */
void nd6_solicited_node_mcast(const uint8_t target[16], uint8_t out[16]);
/* Build an ICMPv6 NS message (cksum=0 placeholder): type135/code0/reserved0/target[16]@8 +
 * SLLA{type1,len1,MAC6}@24 if with_slla. Returns 32 (with SLLA) or 24 (without). */
uint16_t nd6_build_ns(uint8_t *out, const uint8_t target[16], const uint8_t src_mac[6], int with_slla);
/* Build an ICMPv6 NA message: type136/code0/flags=(flags&0xF0)@4/target[16]@8 + TLLA{type2,len1,MAC6}.
 * Returns 32. */
uint16_t nd6_build_na(uint8_t *out, const uint8_t target[16], const uint8_t src_mac[6], uint8_t flags);
/* Parse a received NA: extract target[16], flags byte, and TLLA MAC (if present). Returns 1 if a
 * TLLA MAC was found (mac_out written), 0 otherwise. target_out/flags_out may be NULL. */
int nd6_parse_na(const uint8_t *msg, uint16_t len, uint8_t *target_out, uint8_t *flags_out,
                 uint8_t *mac_out);
/* Parse a received NS: extract target[16] and SLLA MAC (if present). Returns 1 if SLLA found. */
int nd6_parse_ns(const uint8_t *msg, uint16_t len, uint8_t *target_out, uint8_t *mac_out);

/* ---- neighbor cache + state machine ---- */
/* Find a cache entry by IPv6; returns index 0..9 or -1. */
int nd6_find(const uint8_t ip[16]);
/* Find or allocate an entry (new_neighbor 0x0809C368); returns index or -1 if full. */
int nd6_find_or_create(const uint8_t ip[16]);
/* RX: an ICMPv6 message (payload after the 40-byte IPv6 header) with its IPv6 src/dst. Dispatches
 * NS(135)/NA(136)/RA(134) per nd6_input 0x0809C926. */
void nd6_input(const uint8_t *icmp6, uint16_t len, const uint8_t src_ip[16], const uint8_t dst_ip[16]);
/* TX lookup (ethip6_output 0x0809D5D6): resolve dst IPv6 -> MAC. Returns 1 if mac_out written
 * (REACHABLE/DELAY/PROBE, or STALE promoted to DELAY), 0 if pending (entry queued + NS sent). */
int nd6_lookup(const uint8_t dst[16], uint8_t mac_out[6]);
/* 1 s timer tick (nd6_tmr 0x0809D012): reachable countdown, delay->probe, probe retransmit/free. */
void nd6_tmr(void);
/* Send an NS for target (flags bit0 -> solicited-node mcast dst, else unicast). Builds + sends. */
void nd6_send_ns(const uint8_t target[16], uint8_t flags);
/* Send an NA for target to dst (flags: hi-nibble R/S/O, bit0 solicited-mcast dst, bit1 all-nodes). */
void nd6_send_na(const uint8_t target[16], const uint8_t dst[16], uint8_t flags);

#endif /* ND6_H */