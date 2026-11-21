/* nd6.c — IPv6 Neighbor Discovery neighbor cache + NS/NA/RA (REPORT §5.9, Agent N).
 * Faithful INERT replica of the C013 lwIP nd6 layer. Pure state-machine + wire logic host-tested
 * (test_nd6.c); live TX behind a hook (NULL = inert), RX injected (nd6_input). No power GPIO.
 */
#include "nd6.h"
#include "v2g_net.h"

static nd6_t nd6;
static nd6_send_fn send_hook;
static uint8_t tx_buf[128];   /* Eth14 + IP6 40 + ICMPv6 32 = 86 max */
static uint8_t msg[ND6_NS_LEN];

static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }
static void cp(uint8_t *d, const uint8_t *s, uint16_t n) { for (uint16_t i = 0; i < n; i++) d[i] = s[i]; }
static int eq16(const uint8_t *a, const uint8_t *b) { for (uint16_t i = 0; i < 16; i++) if (a[i] != b[i]) return 0; return 1; }
static int is_mcast(const uint8_t *ip) { return ip[0] == 0xFFu; }
static int is_unspecified(const uint8_t *ip) { for (uint16_t i = 0; i < 16; i++) if (ip[i]) return 0; return 1; }
static uint32_t ntohl32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static void put16be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

void nd6_set_send(nd6_send_fn fn) { send_hook = fn; }

void nd6_init(void)
{
    z((uint8_t *)&nd6, sizeof nd6);
    nd6.reachable_time = ND6_REACHABLE_TIME_MS;   /* [?] pre-RA default */
    nd6.retransmit_time = ND6_RETRANS_TIME_MS;
    nd6.cached_neighbor = 0xFFu;
    nd6.cached_router = 0xFFu;
}

void nd6_set_local(const uint8_t ip[16], const uint8_t mac[6])
{
    cp(nd6.local_ip, ip, 16);
    cp(nd6.local_mac, mac, 6);
}

const nd6_t *nd6_get(void) { return &nd6; }

void nd6_solicited_node_mcast(const uint8_t target[16], uint8_t out[16])
{
    /* ff02::1:ffXX:XXXX — word0=0x000002ff, word1=0, word2=0x01000000, word3=target[3]|0xff. */
    z(out, 16);
    out[0] = 0xFFu; out[1] = 0x02u; out[11] = 0x01u; out[12] = 0xFFu;
    out[13] = target[13]; out[14] = target[14]; out[15] = target[15];
}

uint16_t nd6_build_ns(uint8_t *out, const uint8_t target[16], const uint8_t src_mac[6], int with_slla)
{
    /* nd6_send_ns 0x0809C520: type135/code0/cksum0/reserved0/target[16]@8 + SLLA@24. */
    z(out, ND6_NS_LEN);
    out[0] = ND6_ICMP6_NS;
    cp(out + 8, target, 16);
    if (with_slla) {
        out[24] = ND6_OPT_SLLA;   /* type 1 */
        out[25] = 1u;             /* len = (hwaddr_len+9)>>3 = 1 unit (8 octets) */
        cp(out + 26, src_mac, 6);
        return ND6_NS_LEN;
    }
    return 24u;
}

uint16_t nd6_build_na(uint8_t *out, const uint8_t target[16], const uint8_t src_mac[6], uint8_t flags)
{
    /* nd6_send_na 0x0809C7BA: type136/code0/cksum0/flags=(flags&0xF0)@4/target[16]@8 + TLLA@24. */
    z(out, ND6_NA_LEN);
    out[0] = ND6_ICMP6_NA;
    out[4] = (uint8_t)(flags & 0xF0u);   /* R/S/O hi-nibble; low nibble (dst selectors) discarded */
    cp(out + 8, target, 16);
    out[24] = ND6_OPT_TLLA;   /* type 2 */
    out[25] = 1u;
    cp(out + 26, src_mac, 6);
    return ND6_NA_LEN;
}

/* Walk the option area starting at +24 for a link-layer address option of the given type. */
static int parse_lla(const uint8_t *m, uint16_t len, uint8_t opt_type, uint8_t *mac_out)
{
    uint16_t off = 24u;
    while (off + 2u <= len) {
        uint8_t t = m[off];
        uint16_t olen = (uint16_t)m[off + 1] * 8u;
        if (olen == 0) break;
        if (off + olen > len) break;
        if (t == opt_type && olen >= ND6_OPT_MAC_LEN) {
            if (mac_out) cp(mac_out, m + off + 2, 6);
            return 1;
        }
        off = (uint16_t)(off + olen);
    }
    return 0;
}

int nd6_parse_na(const uint8_t *m, uint16_t len, uint8_t *target_out, uint8_t *flags_out, uint8_t *mac_out)
{
    if (len < 24u || m[0] != ND6_ICMP6_NA) return 0;
    if (target_out) cp(target_out, m + 8, 16);
    if (flags_out) *flags_out = m[4];
    return parse_lla(m, len, ND6_OPT_TLLA, mac_out);
}

int nd6_parse_ns(const uint8_t *m, uint16_t len, uint8_t *target_out, uint8_t *mac_out)
{
    if (len < 24u || m[0] != ND6_ICMP6_NS) return 0;
    if (target_out) cp(target_out, m + 8, 16);
    return parse_lla(m, len, ND6_OPT_SLLA, mac_out);
}

int nd6_find(const uint8_t ip[16])
{
    for (uint8_t i = 0; i < ND6_CACHE_SIZE; i++)
        if (nd6.cache[i].state != ND6_STATE_UNUSED && eq16(nd6.cache[i].ip, ip)) return (int)i;
    return -1;
}

int nd6_find_or_create(const uint8_t ip[16])
{
    int idx = nd6_find(ip);
    if (idx >= 0) return idx;
    for (uint8_t i = 0; i < ND6_CACHE_SIZE; i++) {
        if (nd6.cache[i].state == ND6_STATE_UNUSED) {
            nd6_neighbor_t *e = &nd6.cache[i];
            z((uint8_t *)e, sizeof *e);
            cp(e->ip, ip, 16);
            e->state = ND6_STATE_INCOMPLETE;   /* new_neighbor 0x0809C368 */
            return (int)i;
        }
    }
    return -1;
}

/* flush_queue 0x0809C8BA: release queued packets (inert: count only, real pbuf re-send gated). */
static void flush_queue(int idx)
{
    nd6.flushed += nd6.cache[idx].queued;
    nd6.cache[idx].queued = 0;
}

static void free_entry(int idx)
{
    z((uint8_t *)&nd6.cache[idx], sizeof(nd6.cache[idx]));   /* state -> UNUSED(0) */
}

/* Wrap an ICMPv6 message in IPv6(hop255,nh58)+Ethernet and send via the hook. */
static void emit_icmp6(const uint8_t *m, uint16_t mlen, const uint8_t dst_ip[16], const uint8_t dst_mac[6])
{
    uint16_t ck = v2g_net_ip6_pseudo_chksum(nd6.local_ip, dst_ip, V2G_IP6_NH_ICMP6, m, mlen);
    uint8_t framed[ND6_NS_LEN];
    cp(framed, m, mlen);
    put16be(framed + 2, ck);
    uint16_t n = v2g_net_eth_build(tx_buf, dst_mac, nd6.local_mac, V2G_ETHTYPE_IPV6);
    n = (uint16_t)(n + v2g_net_ip6_build(tx_buf + n, mlen, V2G_IP6_NH_ICMP6, 255u, nd6.local_ip, dst_ip));
    cp(tx_buf + n, framed, mlen);
    n = (uint16_t)(n + mlen);
    if (send_hook) send_hook(tx_buf, n);
}

void nd6_send_ns(const uint8_t target[16], uint8_t flags)
{
    uint16_t mlen = nd6_build_ns(msg, target, nd6.local_mac, 1);
    uint8_t dst_ip[16], dst_mac[6];
    if (flags & ND6_NS_FLAG_SOLICITED) {
        nd6_solicited_node_mcast(target, dst_ip);
        v2g_net_ipv6_mcast_mac(dst_ip, dst_mac);
    } else {
        cp(dst_ip, target, 16);
        int idx = nd6_find(target);
        if (idx >= 0) cp(dst_mac, nd6.cache[idx].mac, 6);
        else { nd6_solicited_node_mcast(target, dst_ip); v2g_net_ipv6_mcast_mac(dst_ip, dst_mac); }
    }
    emit_icmp6(msg, mlen, dst_ip, dst_mac);
    nd6.ns_sent++;
}

void nd6_send_na(const uint8_t target[16], const uint8_t dst[16], uint8_t flags)
{
    uint16_t mlen = nd6_build_na(msg, target, nd6.local_mac, flags);
    uint8_t dst_mac[6];
    if (is_mcast(dst)) v2g_net_ipv6_mcast_mac(dst, dst_mac);
    else {
        int idx = nd6_find(dst);
        if (idx >= 0) cp(dst_mac, nd6.cache[idx].mac, 6);
        else z(dst_mac, 6);
    }
    emit_icmp6(msg, mlen, dst, dst_mac);
    nd6.na_sent++;
}

void nd6_input(const uint8_t *icmp6, uint16_t len, const uint8_t src_ip[16], const uint8_t dst_ip[16])
{
    if (len < ND6_ICMP6_HDR_LEN) return;
    uint8_t type = icmp6[0];
    if (type == ND6_ICMP6_NA) {
        /* NA receive 0x0809C962: find_neighbor by TARGET; TLLA MAC copied only if Override set;
         * state=REACHABLE(2) @0x0809CAE6, counter=reachable_time @0x0809CAEE; flush_queue. */
        uint8_t target[16] = {0}, flags = 0, mac[6] = {0};
        int has_mac = nd6_parse_na(icmp6, len, target, &flags, mac);
        int idx = nd6_find(target);
        if (idx < 0) return;
        nd6_neighbor_t *e = &nd6.cache[idx];
        if (has_mac && (flags & ND6_NA_FLAG_O)) cp(e->mac, mac, 6);
        e->state = ND6_STATE_REACHABLE;
        e->counter = nd6.reachable_time;
        flush_queue(idx);
    } else if (type == ND6_ICMP6_NS) {
        /* NS receive 0x0809CC84/88: neighbor by SRC; state=DELAY(4)/counter=5 (DEVIATION from
         * stock STALE=3); SLLA MAC -> entry; if target==own -> NA reply (DAD/solicited). */
        uint8_t target[16] = {0}, mac[6] = {0};
        int has_mac = nd6_parse_ns(icmp6, len, target, mac);
        int idx = nd6_find_or_create(src_ip);
        if (idx >= 0) {
            nd6_neighbor_t *e = &nd6.cache[idx];
            e->state = ND6_STATE_DELAY;
            e->counter = ND6_NS_RECV_COUNTER;
            if (has_mac) cp(e->mac, mac, 6);
        }
        if (eq16(target, nd6.local_ip)) {
            if (is_unspecified(src_ip)) {
                /* DAD probe (src ::) -> NA to all-nodes ff02::1, flags 0x22 (Override). */
                uint8_t allnodes[16]; z(allnodes, 16); allnodes[0] = 0xFFu; allnodes[1] = 0x02u; allnodes[15] = 0x01u;
                nd6_send_na(target, allnodes, ND6_NA_DAD);
            } else {
                /* Solicited NS -> NA unicast to the sender, flags 0x60 (Solicited+Override). */
                nd6_send_na(target, src_ip, ND6_NA_SOLICITED);
            }
        }
    } else if (type == ND6_ICMP6_RA) {
        /* RA receive: reachable_time@+8 (ntohl, only if non-zero) / retrans_timer@+12 (ntohl). */
        nd6.ra_recv++;
        if (len >= 16u) {
            uint32_t rt = ntohl32(icmp6 + 8);
            uint32_t retr = ntohl32(icmp6 + 12);
            if (rt != 0) nd6.reachable_time = rt;
            nd6.retransmit_time = retr;
        }
        int idx = nd6_find_or_create(src_ip);
        if (idx >= 0) nd6.cache[idx].is_router = 1u;
    }
    /* PTB(2)/redirect(137) handled by the wider icmp6 layer; inert here. */
    (void)dst_ip;
}

int nd6_lookup(const uint8_t dst[16], uint8_t mac_out[6])
{
    /* ethip6_output 0x0809B35C: multicast -> 33:33:dst[12..15]. */
    if (is_mcast(dst)) { v2g_net_ipv6_mcast_mac(dst, mac_out); return 1; }
    int idx = nd6_find(dst);
    if (idx < 0) {
        idx = nd6_find_or_create(dst);
        if (idx < 0) return 0;
        nd6.cache[idx].state = ND6_STATE_INCOMPLETE;
        nd6.cache[idx].counter = 0;
        nd6.cache[idx].queued++;
        nd6_send_ns(dst, ND6_NS_FLAG_SOLICITED);   /* queue 0x0809D524 + NS */
        return 0;
    }
    nd6_neighbor_t *e = &nd6.cache[idx];
    if (e->state == ND6_STATE_STALE) {
        e->state = ND6_STATE_DELAY;   /* STALE -> DELAY, counter 5 */
        e->counter = ND6_NS_RECV_COUNTER;
        cp(mac_out, e->mac, 6);
        return 1;
    }
    if (e->state == ND6_STATE_REACHABLE || e->state == ND6_STATE_DELAY || e->state == ND6_STATE_PROBE) {
        cp(mac_out, e->mac, 6);
        return 1;
    }
    /* INCOMPLETE: already soliciting; queue and wait. */
    e->queued++;
    return 0;
}

void nd6_tmr(void)
{
    /* nd6_tmr 0x0809D012 (1 s tick), TBB state enum 0..5. */
    for (uint8_t i = 0; i < ND6_CACHE_SIZE; i++) {
        nd6_neighbor_t *e = &nd6.cache[i];
        switch (e->state) {
        case ND6_STATE_REACHABLE:
            if (e->queued) flush_queue((int)i);
            if (e->counter <= ND6_REACHABLE_TICK_MS) { e->state = ND6_STATE_STALE; e->counter = 0; }
            else e->counter -= ND6_REACHABLE_TICK_MS;
            break;
        case ND6_STATE_DELAY:
            if (e->counter <= 1u) { e->state = ND6_STATE_PROBE; e->counter = 0; }
            else e->counter--;
            break;
        case ND6_STATE_INCOMPLETE:
            if (e->counter >= ND6_MAX_PROBES && !e->is_router) { free_entry((int)i); break; }
            e->counter++;
            nd6_send_ns(e->ip, ND6_NS_FLAG_SOLICITED);   /* multicast solicit (flags 1) */
            break;
        case ND6_STATE_PROBE:
            if (e->counter >= ND6_MAX_PROBES && !e->is_router) { free_entry((int)i); break; }
            e->counter++;
            nd6_send_ns(e->ip, 0u);   /* unicast probe (flags 0) */
            break;
        case ND6_STATE_STALE:
            e->counter++;   /* age */
            break;
        default: break;
        }
    }
}