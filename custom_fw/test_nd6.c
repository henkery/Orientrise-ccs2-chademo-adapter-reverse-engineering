/* test_nd6.c — host unit test for IPv6 ND6 neighbor cache + NS/NA/RA (custom_fw/src/nd6.c, §5.9).
 * Build + run:
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_nd6 \
 *       test_nd6.c src/nd6.c src/v2g_net.c src/v2gtp.c && ./test_nd6'
 * ccs2_rx_exi + sdp_rx are stubbed here (the heavy ccs2/sdp modules are not linked). */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "nd6.h"
#include "v2g_net.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

static uint8_t cap[256]; static uint16_t cap_len; static uint32_t cap_count;
static void capture(const uint8_t *f, uint16_t n) { if (n <= sizeof cap) memcpy(cap, f, n); cap_len = n; cap_count++; }
/* test-only mutable view of the cache (the public getter is const). */
static nd6_t *mut(void) { return (nd6_t *)(uintptr_t)nd6_get(); }
/* stubs for the gated upper-layer entry points referenced by v2g_net.c (not exercised here). */
int ccs2_rx_exi(const uint8_t *frame, uint16_t len, uint32_t now_ms)
{ (void)frame; (void)len; (void)now_ms; return 0; }
void sdp_rx(const uint8_t *buf, uint16_t len) { (void)buf; (void)len; }

static void mk_ip(uint8_t *ip, uint8_t last) { memset(ip, 0, 16); ip[0] = 0xfe; ip[1] = 0x80; ip[15] = last; }
static const uint8_t macA[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
static const uint8_t macB[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

int main(void)
{
    uint8_t local[16], peer[16], tgt[16];
    mk_ip(local, 0x01); mk_ip(peer, 0x02);

    /* --- solicited-node multicast ff02::1:ffXX:XXXX --- */
    mk_ip(tgt, 0x42); tgt[13] = 0xAB; tgt[14] = 0xCD;
    uint8_t sn[16]; nd6_solicited_node_mcast(tgt, sn);
    CHECK(sn[0]==0xff && sn[1]==0x02 && sn[11]==0x01 && sn[12]==0xff, "solicited-node ff02::1:ff prefix");
    CHECK(sn[13]==0xAB && sn[14]==0xCD && sn[15]==0x42, "solicited-node low 24 bits = target[13..15]");
    CHECK(sn[2]==0 && sn[10]==0, "solicited-node middle zero");

    /* --- NS build wire layout (nd6_send_ns 0x0809C520) --- */
    uint8_t ns[40]; uint16_t n = nd6_build_ns(ns, tgt, macA, 1);
    CHECK(n == 32, "NS len 32 (with SLLA)");
    CHECK(ns[0]==135 && ns[1]==0, "NS type 135 code 0");
    CHECK(ns[2]==0 && ns[3]==0 && ns[4]==0 && ns[7]==0, "NS cksum/reserved zero");
    CHECK(memcmp(ns+8, tgt, 16)==0, "NS target @+8");
    CHECK(ns[24]==1 && ns[25]==1, "SLLA type 1 len 1 @+24");
    CHECK(memcmp(ns+26, macA, 6)==0, "SLLA MAC @+26");
    CHECK(nd6_build_ns(ns, tgt, macA, 0)==24, "NS len 24 (no SLLA)");

    /* --- NA build wire layout (nd6_send_na 0x0809C7BA) --- */
    uint8_t na[40]; n = nd6_build_na(na, tgt, macA, ND6_NA_SOLICITED);
    CHECK(n == 32, "NA len 32");
    CHECK(na[0]==136 && na[1]==0, "NA type 136 code 0");
    CHECK(na[4]==0x60, "NA flags byte = 0x60 & 0xF0 (S+O)");
    CHECK(na[5]==0 && na[6]==0 && na[7]==0, "NA reserved zero");
    CHECK(memcmp(na+8, tgt, 16)==0, "NA target @+8");
    CHECK(na[24]==2 && na[25]==1, "TLLA type 2 len 1 @+24");
    CHECK(memcmp(na+26, macA, 6)==0, "TLLA MAC @+26");
    nd6_build_na(na, tgt, macA, ND6_NA_DAD);
    CHECK(na[4]==0x20, "DAD NA flags byte = 0x22 & 0xF0 = 0x20 (O only)");

    /* --- NA/NS parse round-trip --- */
    uint8_t pt[16], pm[6], pf;
    CHECK(nd6_parse_na(na, 32, pt, &pf, pm)==1, "parse NA finds TLLA");
    CHECK(memcmp(pt, tgt, 16)==0 && pf==0x20 && memcmp(pm, macA, 6)==0, "parse NA target/flags/MAC");
    nd6_build_ns(ns, tgt, macB, 1);
    CHECK(nd6_parse_ns(ns, 32, pt, pm)==1, "parse NS finds SLLA");
    CHECK(memcmp(pm, macB, 6)==0, "parse NS SLLA MAC");
    CHECK(nd6_parse_na(na, 23, pt, &pf, pm)==0, "parse NA rejects len<24");

    /* --- cache find / find_or_create --- */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture);
    CHECK(nd6_find(peer) == -1, "find empty -> -1");
    int idx = nd6_find_or_create(peer);
    CHECK(idx == 0, "create first entry idx 0");
    CHECK(mut()->cache[0].state == ND6_STATE_INCOMPLETE, "new entry INCOMPLETE");
    CHECK(memcmp(mut()->cache[0].ip, peer, 16)==0, "new entry IP copied");
    CHECK(nd6_find_or_create(peer) == 0, "find_or_create returns existing");
    CHECK(nd6_find(peer) == 0, "find existing");

    /* --- NS receive: DELAY(4)/counter5 DEVIATION + SLLA MAC + solicited NA reply --- */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture); cap_count = 0;
    nd6_build_ns(ns, local, macB, 1);   /* peer asks for OUR address (target=local) */
    nd6_input(ns, 32, peer, local);
    const nd6_t *g = nd6_get();
    int pi = nd6_find(peer);
    CHECK(pi >= 0, "NS receive created src neighbor");
    CHECK(g->cache[pi].state == ND6_STATE_DELAY, "NS receive state DELAY(4) [deviation, not STALE]");
    CHECK(g->cache[pi].counter == 5, "NS receive counter 5 [deviation]");
    CHECK(memcmp(g->cache[pi].mac, macB, 6)==0, "NS receive SLLA MAC copied");
    CHECK(g->na_sent == 1, "NS for own address -> NA reply sent");
    CHECK(cap_count == 1 && cap_len == 86, "NA reply framed Eth14+IP6 40+ICMPv6 32 = 86");
    CHECK(cap[12]==0x86 && cap[13]==0xDD, "NA reply EtherType IPv6");
    CHECK(cap[14+7]==255, "NA reply IPv6 hop limit 255");
    CHECK(cap[14+6]==58, "NA reply next-header ICMPv6(58)");
    CHECK(cap[54]==136 && cap[54+4]==0x60, "NA reply type 136 flags 0x60 (solicited)");
    CHECK(memcmp(cap+54+8, local, 16)==0, "NA reply target = own address");

    /* --- DAD NS (src ::) -> NA to all-nodes flags 0x22 --- */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture); cap_count = 0;
    uint8_t unspec[16]; memset(unspec, 0, 16);
    nd6_build_ns(ns, local, macB, 1);
    nd6_input(ns, 32, unspec, local);
    CHECK(nd6_get()->na_sent == 1, "DAD NS -> NA sent");
    CHECK(cap[54+4]==0x20, "DAD NA flags 0x20 (Override)");
    CHECK(cap[14+24]==0xff && cap[14+25]==0x02 && cap[14+39]==0x01, "DAD NA dst all-nodes ff02::1");
    CHECK(cap[0]==0x33 && cap[1]==0x33 && cap[5]==0x01, "DAD NA dst MAC 33:33:00:00:00:01");

    /* --- NA receive: REACHABLE(2)/counter=reachable_time, Override-gated MAC, flush --- */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture);
    int e = nd6_find_or_create(peer);
    nd6_get(); memcpy(mut()->cache[e].mac, macA, 6);
    /* queue a packet then resolve via NA */
    uint8_t macout[6];
    nd6_lookup(peer, macout);   /* INCOMPLETE -> queued++ (peer already exists INCOMPLETE) */
    CHECK(mut()->cache[e].queued >= 1, "lookup INCOMPLETE queues packet");
    nd6_build_na(na, peer, macB, ND6_NA_SOLICITED);   /* NA target=peer, TLLA macB, O set */
    nd6_input(na, 32, peer, local);
    CHECK(mut()->cache[e].state == ND6_STATE_REACHABLE, "NA receive state REACHABLE(2)");
    CHECK(mut()->cache[e].counter == ND6_REACHABLE_TIME_MS, "NA receive counter=reachable_time");
    CHECK(memcmp(mut()->cache[e].mac, macB, 6)==0, "NA receive Override -> TLLA MAC updated");
    CHECK(mut()->cache[e].queued == 0, "NA receive flush_queue releases queued");
    CHECK(nd6_get()->flushed >= 1, "flushed count incremented");
    /* NA with Override clear must NOT update an existing MAC */
    memcpy(mut()->cache[e].mac, macA, 6);
    nd6_build_na(na, peer, macB, ND6_NA_FLAG_S);   /* S only, O clear -> flags 0x40 */
    nd6_input(na, 32, peer, local);
    CHECK(memcmp(mut()->cache[e].mac, macA, 6)==0, "NA Override clear -> MAC unchanged");

    /* --- RA receive: reachable/retrans update + is_router --- */
    nd6_init(); nd6_set_local(local, macA);
    uint8_t ra[64]; memset(ra, 0, sizeof ra);
    ra[0] = 134; ra[4] = 64;   /* cur hop limit */
    ra[8]=0; ra[9]=0; ra[10]=0x75; ra[11]=0x30;   /* reachable_time 30000 BE */
    ra[12]=0; ra[13]=0; ra[14]=0x03; ra[15]=0xE8;  /* retrans_timer 1000 BE */
    nd6_input(ra, 16, peer, local);
    CHECK(nd6_get()->reachable_time == 30000, "RA reachable_time 30000");
    CHECK(nd6_get()->retransmit_time == 1000, "RA retransmit_time 1000");
    CHECK(nd6_get()->ra_recv == 1, "RA recv count");
    int ri = nd6_find(peer);
    CHECK(ri >= 0 && mut()->cache[ri].is_router == 1, "RA sender marked router");
    /* reachable_time zero in RA must NOT clear the existing value */
    ra[8]=ra[9]=ra[10]=ra[11]=0;
    nd6_input(ra, 16, peer, local);
    CHECK(nd6_get()->reachable_time == 30000, "RA reachable_time 0 keeps previous");

    /* --- TX lookup: multicast MAC --- */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture);
    uint8_t mcast[16]; memset(mcast,0,16); mcast[0]=0xff; mcast[1]=0x02; mcast[15]=0x01;
    CHECK(nd6_lookup(mcast, macout)==1, "lookup multicast resolved");
    CHECK(macout[0]==0x33 && macout[1]==0x33 && macout[5]==0x01, "multicast MAC 33:33:..:01");

    /* --- TX lookup: new unicast -> INCOMPLETE + NS + pending --- */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture); cap_count = 0;
    CHECK(nd6_lookup(peer, macout)==0, "lookup new unicast pending");
    CHECK(cap_count==1 && nd6_get()->ns_sent==1, "lookup new -> NS sent");
    CHECK(cap[54]==135, "lookup NS type 135");
    int ni = nd6_find(peer);
    CHECK(mut()->cache[ni].state==ND6_STATE_INCOMPLETE && mut()->cache[ni].queued==1, "new entry INCOMPLETE queued");
    /* solicited-node mcast dst for the NS (IPv6 dst @ cap[38..53]) */
    CHECK(cap[14+24]==0xff && cap[14+25]==0x02 && cap[14+39]==peer[15], "NS dst solicited-node mcast");

    /* --- TX lookup: STALE -> DELAY/counter5, MAC returned --- */
    nd6_init(); nd6_set_local(local, macA);
    int si = nd6_find_or_create(peer);
    mut()->cache[si].state = ND6_STATE_STALE;
    memcpy(mut()->cache[si].mac, macB, 6);
    CHECK(nd6_lookup(peer, macout)==1, "lookup STALE returns MAC");
    CHECK(mut()->cache[si].state==ND6_STATE_DELAY && mut()->cache[si].counter==5, "STALE promoted DELAY/5");
    CHECK(memcmp(macout, macB, 6)==0, "STALE lookup MAC correct");
    /* REACHABLE/DELAY/PROBE all return MAC */
    mut()->cache[si].state = ND6_STATE_PROBE;
    CHECK(nd6_lookup(peer, macout)==1, "lookup PROBE returns MAC");

    /* --- nd6_tmr: REACHABLE countdown -> STALE --- */
    nd6_init(); nd6_set_local(local, macA);
    int ti = nd6_find_or_create(peer);
    mut()->cache[ti].state = ND6_STATE_REACHABLE;
    mut()->cache[ti].counter = 2500;
    nd6_tmr();
    CHECK(mut()->cache[ti].counter==1500 && mut()->cache[ti].state==ND6_STATE_REACHABLE, "REACHABLE 2500->1500");
    nd6_tmr();
    CHECK(mut()->cache[ti].counter==500, "REACHABLE 1500->500");
    nd6_tmr();
    CHECK(mut()->cache[ti].state==ND6_STATE_STALE && mut()->cache[ti].counter==0, "REACHABLE 500<=1000 -> STALE/0");

    /* --- nd6_tmr: DELAY countdown -> PROBE --- */
    mut()->cache[ti].state = ND6_STATE_DELAY; mut()->cache[ti].counter = 5;
    nd6_tmr(); CHECK(mut()->cache[ti].counter==4 && mut()->cache[ti].state==ND6_STATE_DELAY, "DELAY 5->4");
    nd6_tmr(); nd6_tmr(); nd6_tmr();   /* 4->3->2->1 */
    CHECK(mut()->cache[ti].counter==1, "DELAY ->1");
    nd6_tmr();
    CHECK(mut()->cache[ti].state==ND6_STATE_PROBE && mut()->cache[ti].counter==0, "DELAY 1<=1 -> PROBE/0");

    /* --- nd6_tmr: INCOMPLETE probe count -> free at >=3 (non-router) --- */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture);
    int ii = nd6_find_or_create(peer);   /* INCOMPLETE counter 0 */
    nd6_tmr(); CHECK(mut()->cache[ii].counter==1 && nd6_get()->ns_sent==1, "INCOMPLETE probe 1 + NS");
    nd6_tmr(); CHECK(mut()->cache[ii].counter==2, "INCOMPLETE probe 2");
    nd6_tmr(); CHECK(mut()->cache[ii].counter==3, "INCOMPLETE probe 3");
    nd6_tmr(); CHECK(mut()->cache[ii].state==ND6_STATE_UNUSED, "INCOMPLETE probe>=3 -> freed");
    /* router entry is NOT freed */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture);
    int rr = nd6_find_or_create(peer);
    mut()->cache[rr].is_router = 1; mut()->cache[rr].counter = 3;
    nd6_tmr();
    CHECK(mut()->cache[rr].state==ND6_STATE_INCOMPLETE && mut()->cache[rr].counter==4, "INCOMPLETE router not freed");

    /* --- nd6_tmr: PROBE unicast NS (flags 0) --- */
    nd6_init(); nd6_set_local(local, macA); nd6_set_send(capture); cap_count=0;
    int pp = nd6_find_or_create(peer);
    mut()->cache[pp].state = ND6_STATE_PROBE; mut()->cache[pp].counter = 0;
    memcpy(mut()->cache[pp].mac, macB, 6);
    nd6_tmr();
    CHECK(cap_count==1 && cap[54]==135, "PROBE tmr sends NS");
    CHECK(memcmp(cap+14+24, peer, 16)==0, "PROBE NS dst unicast target (not mcast)");
    CHECK(memcmp(cap+0, macB, 6)==0, "PROBE NS dst MAC = cached neighbor MAC");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}