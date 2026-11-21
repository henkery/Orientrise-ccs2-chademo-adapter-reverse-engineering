/* slac.h — ISO15118-3 SLAC matching + CP/PP link establishment (REPORT §5.9, Agent B / analyze92).
 *
 * Faithful INERT replica of the C013 EVCC SLAC subprocess (0x0802166E) + top-level MATCH handler
 * (0x08021FCE) that establishes the HomePlug GreenPHY link to the EVSE over the QCA7005 PLC
 * transport (qca7005.c). The MME sequence (EV side), byte-derived from the builders/validators:
 *
 *   CM_SLAC_PARM.REQ      0x6064 -> TX   (builder 0x08021710, len 60, retry timer 200)
 *   CM_SLAC_PARM.CNF      0x6065 <- RX   (validator 0x0802188C: NumSounds10/Timeout6/RspType1)
 *   CM_START_ATTEN_CHAR.IND 0x606A -> TX (builder 0x08021934, len 38, timer 20, window 1200)
 *   CM_ATTEN_CHAR.IND     0x606E <- RX   (validator 0x08021454: 34-byte attenuation profile)
 *   CM_ATTEN_CHAR.RSP     0x606F -> TX   (builder 0x08021404, len 70)
 *   CM_MNBC_SOUND.IND     0x6076 -> TX   (builder 0x080219C4, x10, 16B random sound)
 *   CM_SLAC_MATCH.REQ     0x607C -> TX   (builder 0x08021B8A, len 85, timer 200)
 *   CM_SLAC_MATCH.CNF     0x607D <- RX   (handler 0x08021AE4: NID@0x55[7], NMK@0x5D[16], len109)
 *   CM_SET_KEY.REQ        0x6008 -> TX   (builder 0x08022EB8, len 57, KeyType1/PID4)
 *   CM_SET_KEY.CNF        0x6009 <- RX   (decoder 0x080214D6: result==1 -> link established)
 *
 * Timers (100 Hz ticks): PARM/MATCH.REQ retry 200, post-PARM 80, START_ATTEN 20, atten window
 * 1200, link supervision 17000; retries 3, NumSounds 10, Timeout 6 (x100ms), RspType 1.
 * RunID/sound PRNG = LCG next=(9*seed+7)&0xFFFF (0x08022C9C), two iterations -> 32-bit.
 *
 * Outputs consumed by SDP/DIN: matched EVSE MAC, NID (7B), NMK (16B), link-established flag.
 * MME frames are built byte-by-byte (no rodata templates except the 12-byte MAC header);
 * EtherType 0x88E1, MMV=1 @frame[0xE], MMTYPE lo@0xF hi@0x10.
 *
 * INERT: communication only — drives NO power-stage GPIO. The pure frame builders/validators +
 * PRNG are host-unit-tested (custom_fw/test_slac.c). The matching SM sends via qca7005_frame_send
 * and is driven by slac_rx (MME RX) + slac_step (timers); CP/PP analog signaling is in cp.c.
 */
#ifndef SLAC_H
#define SLAC_H
#include <stdint.h>

/* MMTYPE constants (HomePlug AV / IEEE1901 SLAC + key management). */
#define SLAC_PARM_REQ        0x6064u
#define SLAC_PARM_CNF        0x6065u
#define SLAC_START_ATTEN_IND 0x606Au
#define SLAC_ATTEN_CHAR_IND  0x606Eu
#define SLAC_ATTEN_CHAR_RSP  0x606Fu
#define SLAC_MNBC_SOUND_IND  0x6076u
#define SLAC_MATCH_REQ       0x607Cu
#define SLAC_MATCH_CNF       0x607Du
#define SLAC_SET_KEY_REQ     0x6008u
#define SLAC_SET_KEY_CNF     0x6009u

/* Common Ethernet+MME header byte offsets (frame base). */
#define SLAC_OFF_DEST     0x00u   /* dest MAC[6] (broadcast FFx6 for SLAC)        */
#define SLAC_OFF_SRC      0x06u   /* src MAC[6] = EV host MAC                     */
#define SLAC_OFF_ETHERTYPE 0x0Cu  /* 0x88E1 (stored byte-swapped 0xE188)          */
#define SLAC_OFF_MMV      0x0Eu   /* MMV = 1                                      */
#define SLAC_OFF_MMTYPE_LO 0x0Fu
#define SLAC_OFF_MMTYPE_HI 0x10u
#define SLAC_OFF_APPTYPE  0x13u
#define SLAC_OFF_SECTYPE  0x14u

#define SLAC_ETHTYPE_MME  0x88E1u
#define SLAC_NUM_SOUNDS   10u
#define SLAC_TIMEOUT      6u      /* x100ms = 600ms (ISO15118-3)                  */
#define SLAC_RSP_TYPE     1u
#define SLAC_RETRIES      3u

/* Timers in 100 Hz ticks (10 ms). */
#define SLAC_T_PARM       200u    /* PARM.REQ / MATCH.REQ retry timeout           */
#define SLAC_T_POST_PARM  80u     /* post-PARM.CNF window                         */
#define SLAC_T_ATTEN      20u     /* per-sound / atten tick                       */
#define SLAC_T_ATTEN_WIN  1200u   /* total attenuation window                     */
#define SLAC_T_LINK       17000u  /* post-match link supervision                  */

/* SLAC matching state (replica of the subprocess sequence; stock ctx[0x1c] phases). */
typedef enum {
    SLAC_ST_IDLE = 0,
    SLAC_ST_PARM_REQ,        /* send PARM.REQ, wait CNF                          */
    SLAC_ST_START_ATTEN,     /* send START_ATTEN_CHAR.IND, wait ATTEN_CHAR.IND   */
    SLAC_ST_ATTEN_RSP,       /* send ATTEN_CHAR.RSP                              */
    SLAC_ST_SOUND,           /* send MNBC_SOUND.IND x NumSounds                  */
    SLAC_ST_MATCH_REQ,       /* send MATCH.REQ, wait CNF                         */
    SLAC_ST_SET_KEY,         /* send SET_KEY.REQ, wait CNF                       */
    SLAC_ST_MATCHED,         /* link established (SET_KEY.CNF result==1)         */
    SLAC_ST_FAILED
} slac_state_t;

typedef struct {
    uint8_t  state;            /* slac_state_t                                   */
    uint8_t  evse_mac[6];      /* matched EVSE MAC (from MATCH.CNF src)          */
    uint8_t  run_id[8];        /* RunID (LCG)                                    */
    uint8_t  nid[7];           /* Network ID (from MATCH.CNF, last byte & 0x3f)  */
    uint8_t  nmk[16];          /* Network Membership Key (from MATCH.CNF)        */
    uint8_t  link_up;          /* SET_KEY.CNF result==1                          */
    uint8_t  retries;          /* subprocess retry / sound count                 */
    uint8_t  sound_idx;        /* MNBC sound index                               */
    uint16_t timeout;          /* primary timeout (ticks)                        */
    uint32_t phase_tick;       /* phase-start tick                               */
    uint32_t last_send;        /* last-send tick                                 */
    uint16_t prng_seed;        /* LCG seed                                       */
} slac_t;

void slac_init(void);
/* Drive the matching SM one 100 Hz tick (timers/retries; sends via qca7005_frame_send). */
void slac_step(uint32_t tick);
/* MME RX dispatch (called from the CCS2 RX callback for EtherType 0x88E1 frames). */
void slac_rx(const uint8_t *frame, uint16_t len);
const slac_t *slac_get(void);
/* Published credentials (pointers into the SLAC context; valid once link_up). */
const uint8_t *slac_nid(void);
const uint8_t *slac_nmk(void);
const uint8_t *slac_evse_mac(void);
uint8_t slac_link_up(void);

/* ---- Pure, host-testable helpers (byte-exact vs the C013 builders/validators) ---- */
/* LCG PRNG 0x08022C9C: seed = (9*seed+7)&0xFFFF; returns (next2<<16)|next1 (two iterations). */
uint32_t slac_prng(uint16_t *seed);
/* Common header: broadcast dest + EV MAC src + EtherType 0x88E1 + MMV=1 + MMTYPE. */
void slac_hdr(uint8_t *frame, const uint8_t *ev_mac, uint16_t mmtype);
/* TX builders return the frame length. */
uint16_t slac_build_parm_req(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id);
uint16_t slac_build_start_atten(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id);
uint16_t slac_build_atten_rsp(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id,
                              const uint8_t *atten_profile);
uint16_t slac_build_mnbc_sound(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id,
                              uint8_t sound_idx, const uint8_t *sound16);
uint16_t slac_build_match_req(uint8_t *frame, const uint8_t *ev_mac, const uint8_t *run_id,
                              const uint8_t *evse_mac);
uint16_t slac_build_set_key_req(uint8_t *frame, const uint8_t *nid, const uint8_t *nmk);
/* RX validators return 1 if the frame is a valid matching response. */
int slac_parm_cnf_valid(const uint8_t *frame, uint16_t len, const uint8_t *ev_mac,
                        const uint8_t *run_id);
int slac_atten_ind_valid(const uint8_t *frame, uint16_t len, const uint8_t *ev_mac,
                         const uint8_t *run_id);
int slac_match_cnf_valid(const uint8_t *frame, uint16_t len, const uint8_t *ev_mac,
                         const uint8_t *run_id, const uint8_t *evse_mac);
/* Extract NID[7]/NMK[16] from a validated MATCH.CNF (frame[0x55]/[0x5D]); NID[6] &= 0x3f. */
void slac_match_cnf_credentials(const uint8_t *frame, uint8_t *nid, uint8_t *nmk);
/* SET_KEY.CNF result byte (frame[0x13]); 1 == success. */
int slac_set_key_cnf_result(const uint8_t *frame, uint16_t len);

#endif /* SLAC_H */