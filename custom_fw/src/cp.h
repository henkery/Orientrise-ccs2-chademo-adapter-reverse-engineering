/* cp.h — CCS2 Control Pilot / Proximity Pilot analog signaling (REPORT §5.9, Agent B / analyze92).
 *
 * Faithful INERT replica of the C013 CP/PP monitor logic that feeds the SLAC link + the charge
 * state machine's plug-in input. Byte-derived getters/updaters:
 *   AD_PP   0x08088850 : raw*3300/65520 mV   (PP voltage)
 *   AD_CPD  0x08088878 : raw*3300/32760 mV   (CP duty/DC level)
 *   CP analog 0x08088864: raw*6600/32760 mV  (CP level, x2 rail)
 *   CP_ST   0x08052914 : duty==0 -> 'E' ; PD11!=0 -> 'C' ; else 'B'  (fault fn stubbed -> never 'F')
 *   duty-5  0x08052804 : duty in [30,70] (3.0-7.0%) -> '5' (ISO15118 digital mode) else raw duty
 *   PP plug 0x080527B0 : <=2146 mV x4 -> plugged ; >=2296 mV x4 -> unplugged (binary presence,
 *                        hysteresis + 4-sample debounce; no resistance->ampacity table in C013)
 *   BCB     0x080528DC : PD11 'B'->0 / 'C'->1 ; toggle B->C->B with 200 ms delays (states 26..30)
 *   D_LINK  0x080884BA : PB12 input (PLC modem link status)
 *
 * CP PWM duty/freq are captured by TIM4 input-capture on PD12 (AF2 TIM4_CH1); the C013 storage
 * (duty x10 @0x20000A00, freq @0x200009FE) + getters are confirmed, the TIM4 ISR/init anchors are
 * shifted from C009 (not re-pinned). The raw ADC/TIM4 inputs are parameterized here (main feeds
 * stubs until the CP/PP front-end is built).
 *
 * INERT: communication/link signaling only. BCB (PD11) drive is RECORDED, not executed (gated like
 * the power stage until bench-validated). Pure scaling/state/PP helpers host-tested (test_cp.c).
 */
#ifndef CP_H
#define CP_H
#include <stdint.h>

#define CP_STATE_B   0x42u   /* 'B' — PWM present, BCB open      */
#define CP_STATE_C   0x43u   /* 'C' — BCB engaged / vent         */
#define CP_STATE_E   0x45u   /* 'E' — no PWM                     */
#define CP_STATE_F   0x46u   /* 'F' — fault (stubbed in C013)    */
#define CP_DIGITAL_5 0x35u   /* '5' — 3-7% digital comm mode     */

#define CP_PP_PLUG_MV    2146u   /* 0x862 — <= this x4 -> plugged   */
#define CP_PP_UNPLUG_MV  2296u   /* 0x8f8 — >= this x4 -> unplugged */
#define CP_PP_DEBOUNCE   4u
#define CP_DUTY5_LO      30u     /* 3.0% (duty x10)                 */
#define CP_DUTY5_HI      70u     /* 7.0%                            */
#define CP_BCB_DELAY     200u    /* 0xC8 ms B->C->B toggle delay    */

typedef struct {
    uint16_t pp_mv;        /* AD_PP scaled (mV)                  */
    uint16_t cpd_mv;       /* AD_CPD scaled (mV)                 */
    uint16_t cp_duty;      /* CP PWM duty x10                    */
    uint16_t cp_freq;      /* CP PWM freq (Hz)                   */
    uint8_t  cp_state;     /* 'B'/'C'/'E'                        */
    uint8_t  digital_5;    /* 1 if duty in [30,70]               */
    uint8_t  plug_in;      /* PP presence (0/1)                  */
    uint8_t  d_link;       /* PB12 PLC link status               */
    uint8_t  bcb_action;   /* intended BCB level ('B'/'C'), recorded only */
} cp_t;

/* Pure scaling getters (byte-exact). */
uint16_t cp_ad_pp(uint16_t raw);    /* raw*3300/65520 */
uint16_t cp_ad_cpd(uint16_t raw);   /* raw*3300/32760 */
uint16_t cp_ad_cp(uint16_t raw);    /* raw*6600/32760 */
/* CP state char: duty==0 -> 'E' ; fault!=0 -> 'F' ; PD11!=0 -> 'C' ; else 'B'. */
uint8_t cp_state_char(uint16_t duty, uint8_t pd11, uint8_t fault);
/* duty-5 detector: duty in [30,70] -> '5' (0x35) else raw duty. */
uint8_t cp_duty5(uint16_t duty);
/* PP plug-in updater (hysteresis + 4-debounce). Returns the new state; updates *counter. */
uint8_t cp_pp_update(uint16_t pp_mv, uint8_t *state, uint8_t *counter);

void cp_init(void);
/* Feed one sample of raw CP/PP inputs (parameterized; main stubs until the front-end exists). */
void cp_step(uint16_t pp_raw, uint16_t cpd_raw, uint16_t duty, uint16_t freq,
             uint8_t pd11, uint8_t d_link);
const cp_t *cp_get(void);
uint8_t cp_plug_in(void);

#endif /* CP_H */