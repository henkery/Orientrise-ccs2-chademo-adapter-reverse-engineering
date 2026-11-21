/* test_slac.c — host unit test for SLAC matching (custom_fw/src/slac.c, REPORT §5.9).
 * Tests the byte-exact MME builders/validators/PRNG/credentials + a full matching-sequence walk.
 * The QCA7005 transport is stubbed (records TX frames, returns a fixed EV MAC).
 * Build + run:
 *   nix-shell -p gcc --run 'gcc -O2 -Wall -Wextra -Isrc -o test_slac \
 *       test_slac.c src/slac.c && ./test_slac'
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "slac.h"
#include "qca7005.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; \
    printf("FAIL: %s\n", msg); } } while (0)

/* --- QCA7005 transport stubs --- */
static const uint8_t ev_mac[6] = { 0xFE, 0xFF, 0xFE, 0xFF, 0x00, 0x01 };
static const uint8_t evse_mac[6] = { 0x00, 0xB0, 0x52, 0x11, 0x22, 0x33 };
static uint8_t last_tx[256];
static uint16_t last_tx_len;
int qca7005_frame_send(const uint8_t *f, uint16_t len)
{
    if (len <= sizeof last_tx) memcpy(last_tx, f, len);
    last_tx_len = len;
    return 0;
}
const uint8_t *qca7005_mac(void) { return ev_mac; }

static void cp(uint8_t *d, const uint8_t *s, uint16_t n) { for (uint16_t i = 0; i < n; i++) d[i] = s[i]; }
static uint16_t mt(const uint8_t *f) { return f[0xF] | (f[0x10] << 8); }

int main(void)
{
    uint8_t f[128];

    /* --- LCG PRNG (0x08022C9C): next=(9*seed+7)&0xFFFF, two iterations --- */
    uint16_t seed = 0;
    uint32_t r = slac_prng(&seed);
    /* n1 = 9*0+7 = 7 ; n2 = 9*7+7 = 70 ; seed = 70 ; ret (70<<16)|7 */
    CHECK(r == ((70u << 16) | 7u), "prng(0) = (70<<16)|7");
    CHECK(seed == 70, "prng seed updated to n2=70");
    seed = 0xFFFF;
    r = slac_prng(&seed);
    uint16_t n1 = (uint16_t)(9u * 0xFFFFu + 7u);   /* wraps 16-bit */
    uint16_t n2 = (uint16_t)(9u * n1 + 7u);
    CHECK(r == (((uint32_t)n2 << 16) | n1), "prng wraps 16-bit");

    /* --- common header --- */
    slac_hdr(f, ev_mac, SLAC_PARM_REQ);
    CHECK(f[0] == 0xFF && f[5] == 0xFF, "dest broadcast");
    CHECK(memcmp(f + 6, ev_mac, 6) == 0, "src EV MAC");
    CHECK(f[0xC] == 0x88 && f[0xD] == 0xE1, "EtherType 0x88E1");
    CHECK(f[0xE] == 1, "MMV 1");
    CHECK(f[0xF] == 0x64 && f[0x10] == 0x60, "MMTYPE 0x6064 lo/hi");
    CHECK(f[0x11] == 0 && f[0x12] == 0, "payload prefix 0");

    /* --- PARM.REQ builder (len 60, RunID@0x15) --- */
    uint8_t run_id[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint16_t n = slac_build_parm_req(f, ev_mac, run_id);
    CHECK(n == 60, "PARM.REQ len 60");
    CHECK(mt(f) == SLAC_PARM_REQ, "PARM.REQ MMTYPE");
    CHECK(memcmp(f + 0x15, run_id, 8) == 0, "PARM.REQ RunID@0x15");
    CHECK(f[0x13] == 0 && f[0x14] == 0 && f[0x1d] == 0, "PARM.REQ AppType/SecType/0x1d 0");

    /* --- START_ATTEN_CHAR.IND builder (len 38) --- */
    n = slac_build_start_atten(f, ev_mac, run_id);
    CHECK(n == 38 && mt(f) == SLAC_START_ATTEN_IND, "START_ATTEN len 38 + MMTYPE");
    CHECK(f[0x15] == 10 && f[0x16] == 6 && f[0x17] == 1, "NumSounds10/Timeout6/RspType1");
    CHECK(memcmp(f + 0x18, ev_mac, 6) == 0, "START_ATTEN EVHostMAC@0x18");
    CHECK(memcmp(f + 0x1e, run_id, 8) == 0, "START_ATTEN RunID@0x1e");

    /* --- MATCH.REQ builder (len 85) --- */
    n = slac_build_match_req(f, ev_mac, run_id, evse_mac);
    CHECK(n == 85 && mt(f) == SLAC_MATCH_REQ, "MATCH.REQ len 85 + MMTYPE");
    CHECK(f[0x15] == 0x3e && f[0x16] == 0, "MATCH.REQ length field 0x3e");
    CHECK(memcmp(f + 0x28, ev_mac, 6) == 0, "MATCH.REQ EVHostMAC@0x28");
    CHECK(memcmp(f + 0x3f, evse_mac, 6) == 0, "MATCH.REQ EVSEMAC@0x3f");
    CHECK(memcmp(f + 0x45, run_id, 8) == 0, "MATCH.REQ RunID@0x45");

    /* --- SET_KEY.REQ builder (len 57, KeyType1/PID4, NID mask) --- */
    uint8_t nid[7] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xFF };
    uint8_t nmk[16]; for (int i = 0; i < 16; i++) nmk[i] = (uint8_t)(0xA0 + i);
    n = slac_build_set_key_req(f, nid, nmk);
    CHECK(n == 57 && mt(f) == SLAC_SET_KEY_REQ, "SET_KEY.REQ len 57 + MMTYPE 0x6008");
    CHECK(f[0] == 0x00 && f[1] == 0xB0 && f[2] == 0x52, "SET_KEY dest QCA PIB MAC");
    CHECK(f[0x13] == 1, "SET_KEY KeyType 1 (direct NMK)");
    CHECK(f[0x1c] == 4, "SET_KEY PID 4 (HLE)");
    CHECK(f[0x28] == 1, "SET_KEY [0x28]=1");
    CHECK(memcmp(f + 0x21, nid, 6) == 0, "SET_KEY NID@0x21 first 6");
    CHECK(f[0x27] == (0xFF & 0x3f), "SET_KEY NID[6] masked &0x3f");
    CHECK(memcmp(f + 0x29, nmk, 16) == 0, "SET_KEY NMK@0x29");

    /* --- PARM.CNF validator --- */
    uint8_t cnf[128]; memset(cnf, 0, sizeof cnf);
    slac_hdr(cnf, evse_mac, SLAC_PARM_CNF);   /* dest becomes broadcast; fix to EV MAC */
    cp(cnf, ev_mac, 6);                        /* dest = our MAC */
    cp(cnf + 6, evse_mac, 6);                  /* src = EVSE MAC */
    cnf[0x19] = 10; cnf[0x1a] = 6; cnf[0x1b] = 1;
    cp(cnf + 0x24, run_id, 8);
    CHECK(slac_parm_cnf_valid(cnf, 44, ev_mac, run_id) == 1, "PARM.CNF valid");
    CHECK(slac_parm_cnf_valid(cnf, 43, ev_mac, run_id) == 0, "PARM.CNF reject short");
    cnf[0x19] = 9;
    CHECK(slac_parm_cnf_valid(cnf, 44, ev_mac, run_id) == 0, "PARM.CNF reject NumSounds!=10");
    cnf[0x19] = 10; cnf[0x24] ^= 0xFF;
    CHECK(slac_parm_cnf_valid(cnf, 44, ev_mac, run_id) == 0, "PARM.CNF reject RunID mismatch");

    /* --- MATCH.CNF validator + credentials (NID@0x55, NMK@0x5D) --- */
    uint8_t mcnf[128]; memset(mcnf, 0, sizeof mcnf);
    slac_hdr(mcnf, evse_mac, SLAC_MATCH_CNF);
    cp(mcnf, ev_mac, 6); cp(mcnf + 6, evse_mac, 6);
    mcnf[0x15] = 0x56; mcnf[0x16] = 0;
    cp(mcnf + 0x28, ev_mac, 6); cp(mcnf + 0x3f, evse_mac, 6);
    cp(mcnf + 0x45, run_id, 8);
    cp(mcnf + 0x55, nid, 7); cp(mcnf + 0x5D, nmk, 16);
    CHECK(slac_match_cnf_valid(mcnf, 109, ev_mac, run_id, evse_mac) == 1, "MATCH.CNF valid");
    CHECK(slac_match_cnf_valid(mcnf, 108, ev_mac, run_id, evse_mac) == 0, "MATCH.CNF reject short");
    uint8_t gnid[7], gnmk[16];
    slac_match_cnf_credentials(mcnf, gnid, gnmk);
    CHECK(memcmp(gnid, nid, 7) == 0, "MATCH.CNF NID@0x55 extracted");
    CHECK(memcmp(gnmk, nmk, 16) == 0, "MATCH.CNF NMK@0x5D extracted");

    /* --- SET_KEY.CNF result --- */
    uint8_t kcnf[32]; memset(kcnf, 0, sizeof kcnf);
    slac_hdr(kcnf, ev_mac, SLAC_SET_KEY_CNF);
    kcnf[0x13] = 1;
    CHECK(slac_set_key_cnf_result(kcnf, 20) == 1, "SET_KEY.CNF result 1 (success)");
    kcnf[0x13] = 0;
    CHECK(slac_set_key_cnf_result(kcnf, 20) == 0, "SET_KEY.CNF result 0 (fail)");

    /* --- full matching-sequence walk (SM over stubbed transport) --- */
    slac_init();
    uint32_t tick = 0;
    slac_step(tick);   /* IDLE -> PARM_REQ, sends PARM.REQ */
    CHECK(slac_get()->state == SLAC_ST_PARM_REQ, "walk: PARM_REQ");
    CHECK(last_tx_len == 60 && mt(last_tx) == SLAC_PARM_REQ, "walk: TX PARM.REQ");
    const uint8_t *rid = slac_get()->run_id;
    /* inject PARM.CNF with the SM's RunID */
    memset(cnf, 0, sizeof cnf); slac_hdr(cnf, evse_mac, SLAC_PARM_CNF);
    cp(cnf, ev_mac, 6); cp(cnf + 6, evse_mac, 6);
    cnf[0x19] = 10; cnf[0x1a] = 6; cnf[0x1b] = 1; cp(cnf + 0x24, rid, 8);
    slac_rx(cnf, 44);
    CHECK(slac_get()->state == SLAC_ST_START_ATTEN, "walk: PARM.CNF -> START_ATTEN");
    CHECK(memcmp(slac_get()->evse_mac, evse_mac, 6) == 0, "walk: EVSE MAC latched");
    /* advance to send START_ATTEN, inject ATTEN_CHAR.IND */
    for (int i = 0; i < 30 && slac_get()->state == SLAC_ST_START_ATTEN; i++) { tick += 20; slac_step(tick); }
    uint8_t ind[128]; memset(ind, 0, sizeof ind);
    slac_hdr(ind, evse_mac, SLAC_ATTEN_CHAR_IND); cp(ind, ev_mac, 6); cp(ind + 6, evse_mac, 6);
    ind[0x45] = 1; ind[0x46] = 1; cp(ind + 0x15, ev_mac, 6); cp(ind + 0x1b, rid, 8);
    slac_rx(ind, 0x47);
    CHECK(slac_get()->state == SLAC_ST_ATTEN_RSP, "walk: ATTEN_CHAR.IND -> ATTEN_RSP");
    tick += 20; slac_step(tick);   /* ATTEN_RSP -> SOUND */
    CHECK(slac_get()->state == SLAC_ST_SOUND, "walk: ATTEN_RSP -> SOUND");
    /* run through 10 sounds -> MATCH_REQ */
    for (int i = 0; i < 200 && slac_get()->state == SLAC_ST_SOUND; i++) { tick += 20; slac_step(tick); }
    CHECK(slac_get()->state == SLAC_ST_MATCH_REQ, "walk: 10 sounds -> MATCH_REQ");
    tick += 200; slac_step(tick);  /* send MATCH.REQ */
    CHECK(last_tx_len == 85 && mt(last_tx) == SLAC_MATCH_REQ, "walk: TX MATCH.REQ");
    /* inject MATCH.CNF */
    memset(mcnf, 0, sizeof mcnf); slac_hdr(mcnf, evse_mac, SLAC_MATCH_CNF);
    cp(mcnf, ev_mac, 6); cp(mcnf + 6, evse_mac, 6);
    mcnf[0x15] = 0x56; cp(mcnf + 0x28, ev_mac, 6); cp(mcnf + 0x3f, evse_mac, 6);
    cp(mcnf + 0x45, rid, 8); cp(mcnf + 0x55, nid, 7); cp(mcnf + 0x5D, nmk, 16);
    slac_rx(mcnf, 109);
    CHECK(slac_get()->state == SLAC_ST_SET_KEY, "walk: MATCH.CNF -> SET_KEY");
    CHECK(memcmp(slac_nmk(), nmk, 16) == 0, "walk: NMK stored");
    CHECK(slac_nid()[6] == (nid[6] & 0x3f), "walk: NID[6] masked");
    tick += 200; slac_step(tick);  /* send SET_KEY.REQ */
    CHECK(last_tx_len == 57 && mt(last_tx) == SLAC_SET_KEY_REQ, "walk: TX SET_KEY.REQ");
    /* inject SET_KEY.CNF success */
    memset(kcnf, 0, sizeof kcnf); slac_hdr(kcnf, ev_mac, SLAC_SET_KEY_CNF); kcnf[0x13] = 1;
    slac_rx(kcnf, 20);
    CHECK(slac_get()->state == SLAC_ST_MATCHED, "walk: SET_KEY.CNF -> MATCHED");
    CHECK(slac_link_up() == 1, "walk: link_up 1");

    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}