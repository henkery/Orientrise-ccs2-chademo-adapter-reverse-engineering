/* din70121.h — DIN70121 DC charging application layer (EVCC), REPORT §5.9, Agent D / analyze92.
 *
 * Faithful INERT replica of the C013 DIN70121 EVSE-measurement extraction + CurrentDemand
 * actuation field maps. The EVSE measurement struct ("meas") base is 0x20007570 (confirmed via
 * the EVCC handler prologue 0x080353B2 ldr r4,=0x20007570); evcc_sta = 0x200074E0 = meas-0x90.
 *
 * PhysicalValueType (load-bearing): DIN stores {Value u16, Multiplier s8, Unit}. The firmware
 * keeps factor byte = multiplier+3 internally and writes factor-3 to the wire. The scale
 * converter 0x0804E786 returns a POWER-OF-10 TABLE word (NOT the code): code in [0,6] ->
 * pow10[code] = [1,10,100,1000,10000,100000,1000000], code>=7 -> 0xFF. Real-world value =
 * raw * pow10[factor] / 1000 = raw * 10^(factor-3). (This CORRECTS analyze89's earlier
 * "(code<7)?code:0xFF" reading — the state-30 cap law 0x08044D42 does sxtb in the CALLER then
 * bl 0x804e786 (table lookup) then muls/udiv #1000. The DIN encoder helper 0x0802B92C indexes
 * the same power-of-10 table by signed multiplier in [-3,3].)
 *
 * Measurement map (meas offsets), from CPD Res writer 0x0802BEC0 + CurrentDemandRes decoder
 * 0x0802DC0A:
 *   +0x3D08/+0x3D0A EVSEMaximumVoltageLimit (value/factor)
 *   +0x3D14/+0x3D16 EVSEPresentCurrent
 *   +0x3D18/+0x3D1A EVSEPresentVoltage
 *   +0x3D20/+0x3D22 EVSEMaximumCurrentLimit
 *   +0x3D1B/1C/1D   Current/Voltage/PowerLimitAchieved flags
 * CurrentDemandRes EXI field offsets (decoded-msg struct): maxV [0x22]/[0x20], presentI [0x12]/[0x10],
 *   presentV [0x0E]/[0x0C], maxI [0x28]/[0x26], achieved [0x14]/[0x1C]/[0x18], status [7]/[9]/[6].
 *
 * Actuation: EV targets live at meas[0x3CE0]=EVTargetCurrent, [0x3CE2]=EVTargetVoltage,
 * [0x3CE4]/[0x3CE5] factors. The DIN parameter-setter 0x0802B768 arm 0x606 (0x0802B8F6) copies
 * command{+4 current u16, +6 voltage u16, +8 packed factors (bits0-2 current, bits3-5 voltage)}
 * into meas[0x3CE0/2]. The CurrentDemandReq encoder 0x0802C2CE writes meas[0x3CE0]->EXI[0x18],
 * [0x3CE4]-3->EXI[0x14], meas[0x3CE2]->EXI[0x68], [0x3CE5]-3->EXI[0x64], DC_EVStatus
 * meas[0x3CB7]->EXI[0x40]/[0x3CB8]->EXI[0x48] (EXI[0x44]=1). TX buf 0x20013698 len 108.
 *
 * The full EXI bit-level grammar + the distributed session state machine (timers/retries,
 * FAILED->shutdown) were NOT recovered (Agent D §7) — this replica implements the CONFIRMED
 * measurement + actuation field maps (the bytes the stock encoder/decoder actually moves), with
 * the session sequence / live EXI codec GATED. INERT: communication only, no power-stage GPIO.
 * Pure scaling/decode/encode/setter host-tested (test_din70121.c).
 */
#ifndef DIN70121_H
#define DIN70121_H
#include <stdint.h>

/* CurrentDemandRes EXI field offsets (decoded-msg struct field area). */
#define DIN_CDR_EXI_PRESENT_V   0x0Eu   /* u16 EVSEPresentVoltage value      */
#define DIN_CDR_EXI_PRESENT_V_F 0x0Cu   /* factor (wire multiplier)          */
#define DIN_CDR_EXI_PRESENT_I   0x12u   /* u16 EVSEPresentCurrent value      */
#define DIN_CDR_EXI_PRESENT_I_F 0x10u
#define DIN_CDR_EXI_MAX_V       0x22u   /* u16 EVSEMaximumVoltageLimit value */
#define DIN_CDR_EXI_MAX_V_F     0x20u
#define DIN_CDR_EXI_MAX_I       0x28u   /* u16 EVSEMaximumCurrentLimit value */
#define DIN_CDR_EXI_MAX_I_F     0x26u
#define DIN_CDR_EXI_CUR_ACHIEVED 0x14u
#define DIN_CDR_EXI_VOL_ACHIEVED 0x1Cu
#define DIN_CDR_EXI_PWR_ACHIEVED 0x18u

/* CurrentDemandReq EXI output field offsets. */
#define DIN_CDQ_EXI_TARGET_I    0x18u   /* u16 EVTargetCurrent value         */
#define DIN_CDQ_EXI_TARGET_I_F  0x14u   /* factor-3 (wire multiplier)        */
#define DIN_CDQ_EXI_TARGET_V    0x68u   /* u16 EVTargetVoltage value         */
#define DIN_CDQ_EXI_TARGET_V_F  0x64u
#define DIN_CDQ_EXI_EVREADY     0x40u   /* DC_EVStatus.EVReady               */
#define DIN_CDQ_EXI_EVSTATUS_TAG 0x44u  /* =1                                */
#define DIN_CDQ_EXI_EVERROR     0x48u   /* DC_EVStatus.EVErrorCode           */
#define DIN_CDQ_TX_LEN          108u    /* 0x6C TX image length              */

/* EVSE measurement + EV-target context (mirrors the stock meas field area). Factors are stored
 * as multiplier+3 (the firmware internal convention). */
typedef struct {
    uint16_t evse_max_voltage;       /* +0x3D08 */
    int8_t   evse_max_voltage_f;     /* +0x3D0A */
    uint16_t evse_present_current;   /* +0x3D14 */
    int8_t   evse_present_current_f; /* +0x3D16 */
    uint16_t evse_present_voltage;   /* +0x3D18 */
    int8_t   evse_present_voltage_f; /* +0x3D1A */
    uint16_t evse_max_current;       /* +0x3D20 */
    int8_t   evse_max_current_f;     /* +0x3D22 */
    uint8_t  current_limit_achieved; /* +0x3D1B */
    uint8_t  voltage_limit_achieved; /* +0x3D1C */
    uint8_t  power_limit_achieved;   /* +0x3D1D */
    uint16_t ev_target_current;      /* +0x3CE0 */
    uint16_t ev_target_voltage;      /* +0x3CE2 */
    uint8_t  ev_target_current_f;    /* +0x3CE4 (mult+3) */
    uint8_t  ev_target_voltage_f;    /* +0x3CE5 (mult+3) */
    uint8_t  ev_ready;               /* +0x3CB7 DC_EVStatus.EVReady */
    uint8_t  ev_error_code;          /* +0x3CB8 DC_EVStatus.EVErrorCode */
    uint8_t  first_demand_sent;      /* +0x243 */
} din_meas_t;

/* ---- PhysicalValueType scaling (byte-exact, shared with current_ctrl) ---- */
/* 0x0804E786 table: code in [0,6] -> 10^code ; code>=7 (or <0) -> 0xFF (255, invalid marker). */
uint32_t din_pow10(int8_t code);
/* scale(raw,factor) = (uint16)((uint32)raw * din_pow10(factor) / 1000)  (muls + udiv #1000). */
uint16_t din_scale(uint16_t raw, int8_t factor);

/* ---- measurement extraction ---- */
/* CurrentDemandRes decoder 0x0802DC0A: EXI field map -> meas (factor stored = wire+3). */
void din_cd_res_decode(const uint8_t *exi, din_meas_t *m);
/* Real-unit getters (scale to A / V). */
uint16_t din_evse_max_current_a(const din_meas_t *m);
uint16_t din_evse_present_current_a(const din_meas_t *m);
uint16_t din_evse_max_voltage_v(const din_meas_t *m);
uint16_t din_evse_present_voltage_v(const din_meas_t *m);

/* ---- actuation ---- */
/* parameter-setter arm 0x606 (0x0802B8F6): command{current u16, voltage u16, packed factors}
 * -> meas[0x3CE0/2]; factors bits0-2 current mult, bits3-5 voltage mult (stored mult+3). */
void din_set_ev_target(din_meas_t *m, uint16_t current, uint16_t voltage, uint8_t packed_factors);
/* CurrentDemandReq encoder 0x0802C2CE (EV-target + DC_EVStatus field map): meas -> EXI output.
 * Writes factor-3 to the wire; sets first_demand_sent. `exi` must be >= DIN_CDQ_TX_LEN bytes. */
void din_cd_req_encode(din_meas_t *m, uint8_t *exi);

void din70121_init(void);
const din_meas_t *din70121_meas(void);
din_meas_t *din70121_meas_mut(void);

#endif /* DIN70121_H */