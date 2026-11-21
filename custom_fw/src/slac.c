/* slac.c — ISO15118-3 SLAC matching (REPORT §5.9, Agent B / analyze92).
 * Faithful INERT replica of the C013 EVCC SLAC subprocess + MATCH handler. Communication only —
 * drives NO power-stage GPIO. Pure builders/validators/PRNG host-tested (test_slac.c); the SM
 * sends MMEs via qca7005_frame_send and is driven by slac_rx + slac_step. No libc mem* (loops).
 */
#include "slac.h"
#include "qca7005.h"

static slac_t slac;
static uint8_t atten_profile[34];   /* CM_ATTEN_CHAR.IND profile echoed in the RSP */

/* ---- tiny mem helpers (freestanding: no libc) ---- */
static void z(uint8_t *p, uint16_t n) { for (uint16_t i = 0; i < n; i++) p[i] = 0; }
static void cp(uint8_t *d, const uint8_t *s, uint16_t n) { for (uint16_t i = 0; i < n; i++) d[i] = s[i]; }
static int eq(const uint8_t *a, const uint8_t *b, uint16_t n)
{
    for (uint16_t i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

uint32_t slac_prng(uint16_t *seed)
{
    /* 0x08022C9C: mla r1,9,seed,7 ; uxth (mask 0xFFFF) ; mla r0,9,r1,7 ; orr r0,r1,r0<<16. */
    uint16_t s = *seed;
    uint16_t n1 = (uint16_t)(9u * s + 7u);
    uint16_t n2 = (uint16_t)(9u * n1 + 7u);
    *seed = n2;
    return ((uint32_t)n2 << 16) | (uint32_t)n1;
}

void slac_hdr(uint8_t *frame, const uint8_t *ev_mac, uint16_t mmtype)
{
    /* 0x080213D4: dest broadcast FFx6 ; src EV MAC ; EtherType 0x88E1 ; MMV=1 ; [0x11]=[0x12]=0. */
    for (uint16_t i = 0; i < 6; i++) frame[SLAC_OFF_DEST + i] = 0xFFu;
    cp(frame + SLAC_OFF_SRC, ev_mac, 6);
    frame[SLAC_OFF_ETHERTYPE]      = (uint8_t)(SLAC_ETHTYPE_MME >> 8);    /* 0x88 */
    frame[SLAC_OFF_ETHERTYPE + 1]  = (uint8_t)(SLAC_ETHTYPE_MME & 0xFFu); /* 0xE1 */
    frame[SLAC_OFF_MMV]            = 1u;
    frame[SLAC_OFF_MMTYPE_LO]      = (uint8_t)(mmtype & 0xFFu);
    frame[SLAC_OFF_MMTYPE_HI]      = (uint8_t)(mmtype >> 8);
    frame[0x11] = 0; frame[0x12] = 0;
}

uint16_t slac_build_parm_req(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id)
{
    /* 0x08021710: len 60. AppType/SecType 0 ; RunID@[0x15..0x1c] ; [0x1d]=0 ; memset 30B@0x1e. */
    z(frame, 60);
    slac_hdr(frame, ev_mac, SLAC_PARM_REQ);
    frame[SLAC_OFF_APPTYPE] = 0; frame[SLAC_OFF_SECTYPE] = 0;
    cp(frame + 0x15, run_id, 8);
    frame[0x1d] = 0;
    return 60;
}

uint16_t slac_build_start_atten(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id)
{
    /* 0x08021934: len 38. NumSounds10@0x15 Timeout6@0x16 RspType1@0x17 ; EVHostMAC@0x18 ; RunID@0x1e. */
    z(frame, 38);
    slac_hdr(frame, ev_mac, SLAC_START_ATTEN_IND);
    frame[SLAC_OFF_APPTYPE] = 0; frame[SLAC_OFF_SECTYPE] = 0;
    frame[0x15] = SLAC_NUM_SOUNDS;
    frame[0x16] = SLAC_TIMEOUT;
    frame[0x17] = SLAC_RSP_TYPE;
    cp(frame + 0x18, ev_mac, 6);
    cp(frame + 0x1e, run_id, 8);
    return 38;
}

uint16_t slac_build_atten_rsp(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id,
                              const uint8_t *atten)
{
    /* 0x08021404: len 70. EVHostMAC@0x15 ; RunID@0x1b ; attenuation profile (34B) @0x23. */
    z(frame, 70);
    slac_hdr(frame, ev_mac, SLAC_ATTEN_CHAR_RSP);
    frame[SLAC_OFF_APPTYPE] = 0; frame[SLAC_OFF_SECTYPE] = 0;
    cp(frame + 0x15, ev_mac, 6);
    cp(frame + 0x1b, run_id, 8);
    if (atten) cp(frame + 0x23, atten, 34);
    return 70;
}

uint16_t slac_build_mnbc_sound(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id,
                              uint8_t sound_idx, const uint8_t *sound16)
{
    /* 0x080219C4: len 71. idx@0x26 ; RunID@0x27 ; 16B sound @0x37 (4 words 0x37/3b/3f/43). */
    z(frame, 71);
    slac_hdr(frame, ev_mac, SLAC_MNBC_SOUND_IND);
    frame[SLAC_OFF_APPTYPE] = 0; frame[SLAC_OFF_SECTYPE] = 0;
    frame[0x26] = sound_idx;
    cp(frame + 0x27, run_id, 8);
    if (sound16) cp(frame + 0x37, sound16, 16);
    return 71;
}

uint16_t slac_build_match_req(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id,
                              const uint8_t *evse_mac)
{
    /* 0x08021B8A: len 85. [0x15]=0x3e len ; EVHostMAC@0x28 ; EVSEMAC@0x3f ; RunID@0x45. */
    z(frame, 85);
    slac_hdr(frame, ev_mac, SLAC_MATCH_REQ);
    frame[0x15] = 0x3e; frame[0x16] = 0;
    cp(frame + 0x28, ev_mac, 6);
    cp(frame + 0x3f, evse_mac, 6);
    cp(frame + 0x45, run_id, 8);
    return 85;
}

uint16_t slac_build_set_key_req(uint8_t *frame, const uint8_t *nid, const uint8_t *nmk)
{
    /* 0x08022EB8: len 57. dest QCA PIB 00:B0:52:00:00:01 src FE:FF:FE:FF:00:01 ; KeyType1@0x13 ;
     * PID4@0x1c ; [0x28]=1 ; NID@0x21 (last&0x3f) ; NMK@0x29. */
    static const uint8_t mac_hdr[12] = {
        0x00, 0xB0, 0x52, 0x00, 0x00, 0x01,   /* dest = QCA default PIB MAC */
        0xFE, 0xFF, 0xFE, 0xFF, 0x00, 0x01    /* src  = host */
    };
    z(frame, 57);
    cp(frame, mac_hdr, 12);
    frame[SLAC_OFF_ETHERTYPE]     = (uint8_t)(SLAC_ETHTYPE_MME >> 8);
    frame[SLAC_OFF_ETHERTYPE + 1] = (uint8_t)(SLAC_ETHTYPE_MME & 0xFFu);
    frame[SLAC_OFF_MMV]           = 1u;
    frame[0x11] = 0; frame[0x12] = 0;
    frame[SLAC_OFF_MMTYPE_LO]     = (uint8_t)(SLAC_SET_KEY_REQ & 0xFFu);  /* 0x08 */
    frame[SLAC_OFF_MMTYPE_HI]     = (uint8_t)(SLAC_SET_KEY_REQ >> 8);     /* 0x60 */
    frame[0x13] = 1u;   /* KeyType = direct NMK */
    frame[0x1c] = 4u;   /* PID = HLE */
    frame[0x28] = 1u;
    cp(frame + 0x21, nid, 7);
    frame[0x27] &= 0x3fu;   /* NID is 54 bits + 2 reserved */
    cp(frame + 0x29, nmk, 16);
    frame[0x39] = 0;        /* clear success flag */
    return 57;
}

/* ---- RX validators ---- */
static uint16_t mmtype_of(const uint8_t *f)
{
    return (uint16_t)f[SLAC_OFF_MMTYPE_LO] | ((uint16_t)f[SLAC_OFF_MMTYPE_HI] << 8);
}
static int dest_is(const uint8_t *f, const uint8_t *mac) { return eq(f + SLAC_OFF_DEST, mac, 6); }

int slac_parm_cnf_valid(const uint8_t *frame, uint16_t len, const uint8_t *ev_mac,
                        const uint8_t *run_id)
{
    /* 0x0802188C: dest==our MAC ; len>=44 ; [0x22]=[0x23]=0 ; NumSounds10/Timeout6/RspType1 ;
     * RunID@[0x24..0x2b]==ctx. */
    if (len < 44) return 0;
    if (mmtype_of(frame) != SLAC_PARM_CNF) return 0;
    if (!dest_is(frame, ev_mac)) return 0;
    if (frame[0x22] != 0 || frame[0x23] != 0) return 0;
    if (frame[0x19] != SLAC_NUM_SOUNDS) return 0;
    if (frame[0x1a] != SLAC_TIMEOUT) return 0;
    if (frame[0x1b] != SLAC_RSP_TYPE) return 0;
    if (!eq(frame + 0x24, run_id, 8)) return 0;
    return 1;
}

int slac_atten_ind_valid(const uint8_t *frame, uint16_t len, const uint8_t *ev_mac,
                         const uint8_t *run_id)
{
    /* 0x08021454: dest==our MAC ; [0x13]=[0x14]=0 ; [0x45]!=0,[0x46]!=0 ; EVHostMAC@0x15==our ;
     * RunID@0x1b==ctx ; profile@0x23 (34B). */
    if (len < 0x47) return 0;
    if (mmtype_of(frame) != SLAC_ATTEN_CHAR_IND) return 0;
    if (!dest_is(frame, ev_mac)) return 0;
    if (frame[0x13] != 0 || frame[0x14] != 0) return 0;
    if (frame[0x45] == 0 || frame[0x46] == 0) return 0;
    if (!eq(frame + 0x15, ev_mac, 6)) return 0;
    if (!eq(frame + 0x1b, run_id, 8)) return 0;
    return 1;
}

int slac_match_cnf_valid(const uint8_t *frame, uint16_t len, const uint8_t *ev_mac,
                         const uint8_t *run_id, const uint8_t *evse_mac)
{
    /* 0x08023046: dest==our MAC ; len>=109 ; [0x13]=[0x14]=0 ; [0x15]=0x56,[0x16]=0 ;
     * EVHostMAC@0x28==our ; EVSEMAC@0x3f==ctx[0x1e] ; reserved zero ; RunID@0x45==ctx. */
    if (len < 109) return 0;
    if (mmtype_of(frame) != SLAC_MATCH_CNF) return 0;
    if (!dest_is(frame, ev_mac)) return 0;
    if (frame[0x13] != 0 || frame[0x14] != 0) return 0;
    if (frame[0x15] != 0x56 || frame[0x16] != 0) return 0;
    if (!eq(frame + 0x28, ev_mac, 6)) return 0;
    if (!eq(frame + 0x3f, evse_mac, 6)) return 0;
    for (uint16_t i = 0x17; i <= 0x27; i++) if (frame[i] != 0) return 0;
    for (uint16_t i = 0x2e; i <= 0x3e; i++) if (frame[i] != 0) return 0;
    if (!eq(frame + 0x45, run_id, 8)) return 0;
    return 1;
}

void slac_match_cnf_credentials(const uint8_t *frame, uint8_t *nid, uint8_t *nmk)
{
    /* 0x08021AE4 (adds r5,#9 -> absolute): NMK@0x5D[16] ; NID@0x55[7]. */
    cp(nmk, frame + 0x5D, 16);
    cp(nid, frame + 0x55, 7);
}

int slac_set_key_cnf_result(const uint8_t *frame, uint16_t len)
{
    /* 0x080214D6: MMTYPE 0x6009 ; result @frame[0x13] (1==success). */
    if (len < 0x14) return -1;
    if (mmtype_of(frame) != SLAC_SET_KEY_CNF) return -1;
    return frame[0x13];
}

/* ---- matching state machine (drives qca7005 transport) ---- */
static uint8_t frame_buf[128];

static void send_frame(uint16_t len) { (void)qca7005_frame_send(frame_buf, len); }

static void new_run_id(void)
{
    uint32_t a = slac_prng(&slac.prng_seed);
    uint32_t b = slac_prng(&slac.prng_seed);
    for (uint16_t i = 0; i < 4; i++) {
        slac.run_id[i]     = (uint8_t)(a >> (8 * i));
        slac.run_id[i + 4] = (uint8_t)(b >> (8 * i));
    }
}

void slac_init(void)
{
    z((uint8_t *)&slac, sizeof slac);
    z(atten_profile, sizeof atten_profile);
    slac.state = SLAC_ST_IDLE;
    slac.prng_seed = 0x1234u;   /* stock seeds via 0x0808923A; fixed seed for the inert replica */
}

void slac_step(uint32_t tick)
{
    const uint8_t *ev_mac = qca7005_mac();
    if (!ev_mac) return;                 /* transport not up yet */

    switch (slac.state) {
    case SLAC_ST_IDLE:
        new_run_id();
        slac.retries = SLAC_RETRIES;
        slac.state = SLAC_ST_PARM_REQ;
        slac.phase_tick = tick;
        /* fall through to send PARM.REQ */
        /* fallthrough */
    case SLAC_ST_PARM_REQ:
        if ((uint32_t)(tick - slac.last_send) >= slac.timeout || slac.last_send == 0) {
            if (slac.retries == 0) { slac.state = SLAC_ST_FAILED; break; }
            slac.retries--;
            slac_build_parm_req(frame_buf, ev_mac, slac.run_id);
            send_frame(60);
            slac.last_send = tick;
            slac.timeout = SLAC_T_PARM;
        }
        break;
    case SLAC_ST_START_ATTEN:
        if ((uint32_t)(tick - slac.phase_tick) >= SLAC_T_ATTEN_WIN) {
            slac.state = SLAC_ST_FAILED; break;
        }
        if ((uint32_t)(tick - slac.last_send) >= slac.timeout) {
            slac_build_start_atten(frame_buf, ev_mac, slac.run_id);
            send_frame(38);
            slac.last_send = tick;
            slac.timeout = SLAC_T_ATTEN;
        }
        break;
    case SLAC_ST_ATTEN_RSP:
        slac_build_atten_rsp(frame_buf, ev_mac, slac.run_id, atten_profile);
        send_frame(70);
        slac.sound_idx = 0;
        slac.retries = SLAC_NUM_SOUNDS;
        slac.state = SLAC_ST_SOUND;
        slac.last_send = tick;
        slac.timeout = SLAC_T_ATTEN;
        break;
    case SLAC_ST_SOUND:
        if ((uint32_t)(tick - slac.last_send) >= slac.timeout) {
            if (slac.retries == 0) {
                slac.state = SLAC_ST_MATCH_REQ;
                slac.retries = SLAC_RETRIES;
                slac.last_send = 0;
                slac.timeout = SLAC_T_PARM;
                break;
            }
            uint8_t sound[16];
            for (uint16_t i = 0; i < 4; i++) {
                uint32_t r = slac_prng(&slac.prng_seed);
                sound[i * 4]     = (uint8_t)(r >> 24);
                sound[i * 4 + 1] = (uint8_t)(r >> 16);
                sound[i * 4 + 2] = (uint8_t)(r >> 8);
                sound[i * 4 + 3] = (uint8_t)(r);
            }
            slac_build_mnbc_sound(frame_buf, ev_mac, slac.run_id, slac.sound_idx, sound);
            send_frame(71);
            slac.sound_idx++;
            slac.retries--;
            slac.last_send = tick;
        }
        break;
    case SLAC_ST_MATCH_REQ:
        if ((uint32_t)(tick - slac.last_send) >= slac.timeout || slac.last_send == 0) {
            if (slac.retries == 0) { slac.state = SLAC_ST_FAILED; break; }
            slac.retries--;
            slac_build_match_req(frame_buf, ev_mac, slac.run_id, slac.evse_mac);
            send_frame(85);
            slac.last_send = tick;
            slac.timeout = SLAC_T_PARM;
        }
        break;
    case SLAC_ST_SET_KEY:
        if ((uint32_t)(tick - slac.last_send) >= slac.timeout || slac.last_send == 0) {
            if (slac.retries == 0) { slac.state = SLAC_ST_FAILED; break; }
            slac.retries--;
            slac_build_set_key_req(frame_buf, slac.nid, slac.nmk);
            send_frame(57);
            slac.last_send = tick;
            slac.timeout = SLAC_T_PARM;
        }
        break;
    case SLAC_ST_MATCHED:
        /* link supervision: stock ctx[0xc]=17000; D_LINK (PB12) monitored by cp.c. */
        break;
    default:
        break;
    }
}

void slac_rx(const uint8_t *frame, uint16_t len)
{
    if (len < 17) return;
    if (frame[SLAC_OFF_ETHERTYPE] != 0x88 || frame[SLAC_OFF_ETHERTYPE + 1] != 0xE1) return;
    const uint8_t *ev_mac = qca7005_mac();
    if (!ev_mac) return;
    uint16_t mt = mmtype_of(frame);

    switch (slac.state) {
    case SLAC_ST_PARM_REQ:
        if (mt == SLAC_PARM_CNF && slac_parm_cnf_valid(frame, len, ev_mac, slac.run_id)) {
            cp(slac.evse_mac, frame + SLAC_OFF_SRC, 6);   /* latch EVSE MAC from CNF src */
            slac.timeout = SLAC_T_POST_PARM;
            slac.retries = SLAC_RETRIES;
            slac.state = SLAC_ST_START_ATTEN;
            slac.phase_tick = slac.last_send;
            slac.last_send = 0;
            slac.timeout = SLAC_T_ATTEN;
        }
        break;
    case SLAC_ST_START_ATTEN:
        if (mt == SLAC_ATTEN_CHAR_IND && slac_atten_ind_valid(frame, len, ev_mac, slac.run_id)) {
            cp(atten_profile, frame + 0x23, 34);
            slac.state = SLAC_ST_ATTEN_RSP;
        }
        break;
    case SLAC_ST_MATCH_REQ:
        if (mt == SLAC_MATCH_CNF &&
            slac_match_cnf_valid(frame, len, ev_mac, slac.run_id, slac.evse_mac)) {
            slac_match_cnf_credentials(frame, slac.nid, slac.nmk);
            slac.nid[6] &= 0x3fu;
            slac.timeout = SLAC_T_LINK;
            slac.retries = SLAC_RETRIES;
            slac.state = SLAC_ST_SET_KEY;
            slac.last_send = 0;
            slac.timeout = SLAC_T_PARM;
        }
        break;
    case SLAC_ST_SET_KEY:
        if (mt == SLAC_SET_KEY_CNF) {
            int r = slac_set_key_cnf_result(frame, len);
            if (r == 1) {
                slac.link_up = 1;
                slac.state = SLAC_ST_MATCHED;
            } else if (r >= 0) {
                slac.state = SLAC_ST_FAILED;
            }
        }
        break;
    default:
        break;
    }
}

const slac_t *slac_get(void) { return &slac; }
const uint8_t *slac_nid(void) { return slac.nid; }
const uint8_t *slac_nmk(void) { return slac.nmk; }
const uint8_t *slac_evse_mac(void) { return slac.evse_mac; }
uint8_t slac_link_up(void) { return slac.link_up; }