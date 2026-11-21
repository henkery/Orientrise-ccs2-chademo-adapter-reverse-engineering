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
#include "exi.h"

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

/* CurrentDemandReq EXI output field offsets — CORRECTED by analyze101 (packer 0x0802C2CE / ev11
 * grammar): EVTargetCurrent value @0x14 (factor @0x18), EVTargetVoltage value @0x64 (factor @0x68).
 * The byte @0x40 is BulkChargingComplete (gate @0x44) and @0x48 is ChargingComplete — NOT
 * DC_EVStatus.EVReady/EVErrorCode (those live in the DC_EVStatus sub-production @body+0x00). */
#define DIN_CDQ_EXI_TARGET_I    0x14u   /* u16 EVTargetCurrent value         */
#define DIN_CDQ_EXI_TARGET_I_F  0x18u   /* factor-3 (wire multiplier)        */
#define DIN_CDQ_EXI_TARGET_V    0x64u   /* u16 EVTargetVoltage value         */
#define DIN_CDQ_EXI_TARGET_V_F  0x68u
#define DIN_CDQ_EXI_BULK_COMPLETE 0x40u /* BulkChargingComplete (bool)       */
#define DIN_CDQ_EXI_BULK_GATE   0x44u   /* =1 (BulkChargingComplete gate)    */
#define DIN_CDQ_EXI_CHG_COMPLETE 0x48u  /* ChargingComplete (bool)           */
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
    uint8_t  ev_ready;               /* DC_EVStatus.EVReady (ev17, meas+0x3C97 area) */
    uint8_t  ev_error_code;          /* DC_EVStatus.EVErrorCode (ev17)               */
    uint8_t  bulk_charging_complete; /* +0x3CB7 -> CDReq EXI[0x40] (analyze101)      */
    uint8_t  charging_complete;      /* +0x3CB8 -> CDReq EXI[0x48] (analyze101)      */
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

/* ---- EXI grammar message codec (Agent E / analyze93; bit-level via exi.c primitives) ----
 * The stock codec is a generated grammar-table-driven processor (OpenV2G style): root reads a
 * 7-bit event, tbb-dispatches to 81 productions; each production decodes/encodes its fields with
 * the shared primitive layer (exi.c). These functions replicate the DIN DC message field lists
 * recovered byte-exactly (CurrentDemandRes complete; CableCheck/PreCharge/SessionStop confirmed),
 * operating on the EXI BODY (after the 8-byte V2GTP header + leading 0x80 + 7-bit event, which the
 * session layer handles via exi_decode_header/exi_encode_header). Root events use the CORRECTED
 * ground-truth numbering (exi.h EXI_EV_*; E §1 was +2-shifted in the b-thunk region).
 *
 * DC_EVSEStatus (0x0806259E) — RESOLVED by analyze103: a SINGLE merged grammar with NO DIN/ISO
 * mode flag. Wire order isolation_status(2) -> status_code(4) -> NotificationMaxDelay(u32,
 * MANDATORY, present in DIN) -> notification(2); the isolation element is optional via a 2-bit
 * presence code E0 (0=present/1=absent/>=2=err). 22 fixed bits + one u32, 12 one-bit gates all 0.
 * The replica extracts isolation (load-bearing for the session CableCheck rule) + status code +
 * notification + max delay. NOTE: the charge_stm engagement guard tests the EVSE charge-phase
 * status (meas+0x3D1E ==4), NOT this DIN isolation — see the three-signal split (ccs2/charge_stm). */
typedef struct {
    uint8_t  isolation_status;   /* EVSEIsolationStatus: 0 invalid/1 valid/2 warning/3 fault */
    uint8_t  isolation_present;
    uint8_t  notification;       /* EVSENotification (2-bit enum)                          */
    uint8_t  status_code;        /* EVSEStatusCode (4-bit enum)                            */
    uint32_t notification_max_delay; /* u32 varlen, MANDATORY (analyze103)                 */
} din_dc_evse_status_t;

/* Decode DC_EVSEStatus from the body stream (advances s). Returns EXI_OK / negative error. */
int din_dc_evse_status_decode(exi_stream_t *s, din_dc_evse_status_t *out);

/* CurrentDemandRes grammar decoder 0x0806471E (ev0x12, 10 fields): ResponseCode(5-bit),
 * DC_EVSEStatus, EVSEPresentVoltage PVT, EVSEPresentCurrent PVT, Current/Voltage/PowerLimitAchieved
 * bools, optional EVSEMaximumVoltage/Current/PowerLimit PVTs. Populates meas (factor = mult+3).
 * `response_code` returns the 5-bit ResponseCode (0 = OK). The optional max-limit choice chain
 * (state 0x23 readBits3 / 0x24-0x25 readBits2) follows the recovered wire order [? exact grammar]. */
int din_cd_res_decode_exi(const uint8_t *body, uint16_t len, din_meas_t *m, uint8_t *response_code);

/* CableCheckRes grammar decoder 0x08066C5C (ev0x05): ResponseCode(5-bit), DC_EVSEStatus,
 * EVSEProcessingState(1-bit). Returns isolation status via DC_EVSEStatus; processing 0=finished/
 * 1=ongoing. `response_code`/`processing`/`isolation` outputs. */
int din_cablecheck_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code,
                                  uint8_t *processing, din_dc_evse_status_t *status);

/* PreChargeRes grammar decoder 0x08063A8A (ev0x30): ResponseCode(5-bit), DC_EVSEStatus,
 * EVSEPresentVoltage PVT -> meas.evse_present_voltage (+factor). */
int din_precharge_res_decode_exi(const uint8_t *body, uint16_t len, din_meas_t *m,
                                 uint8_t *response_code, din_dc_evse_status_t *status);

/* SessionStopRes grammar decoder ev43 0x08062A7E (subev 0x20): EMPTY message (1-bit choice
 * 0=empty/valid, 1=err -110). CORRECTED by analyze102 (was mis-mapped to ev1e 0x08063C04). */
int din_sessionstop_res_decode_exi(const uint8_t *body, uint16_t len);

/* ---- B2 DIN document message codec (analyze101/102/103) ----
 * All messages ride the DIN document framing (exi.h: root 0x4D + header + 6-bit choice/subev).
 * Req encoders write the FULL document (8-byte V2GTP reserved at [0..7] + leading 0x80 + root
 * 0x4D + DIN header + 6-bit choice + body + EE gate) into buf[cap], returning total length or a
 * negative EXI error. Res decoders operate on the BODY (after the framing, which ccs2_rx_exi
 * strips via exi_decode_header + exi_din_decode_doc_start). INERT: images only; live send gated;
 * no power GPIO. `sid`/`sid_len` = the DIN header SessionID (gid 0x6c). */

/* DC_EVStatus (ev17 0x0806A936) encoder — the EV->EVSE status sub-production shared by CableCheck/
 * PreCharge/CurrentDemand/Welding/CPD Req. Recovered default grammar (builder presence flags
 * [body+8]/[body+0x10]=0): gate0 gate0 EVReady(bool) gate0 + choice(2,2) gate0 4-bit(0) gate0 +
 * gate0 gate0 EVRESSSOC(7-bit) gate0 + terminal gate0 (23 bits). `soc` = 7-bit percent (the stock
 * CableCheck builder default is 0x46 = 70). Writes the body sub-stream (advances s). */
int din_dc_ev_status_encode(exi_stream_t *s, uint8_t ev_ready, uint8_t soc);

/* CPD Res DC_EVSEChargeParameter (ev15 0x080650D2) — the EVSE DC limits (analyze102). Wire order:
 * DC_EVSEStatus@+0, maxCurrent PVT@+0xC (req), maxPower PVT@+0x14 (opt), maxVoltage@+0x20 (req),
 * minCurrent@+0x28 (req), minVoltage@+0x30 (req), opt PVT@+0x38 (opt), PVT@+0x44 (req), energy
 * PVT@+0x4C (opt). Optional fields use a 2-bit choice (0=present+flag, 1=skip). */
typedef struct {
    din_dc_evse_status_t status;   /* DC_EVSEStatus @+0                          */
    exi_pvt_t max_current;         /* EVSEMaximumCurrentLimit @+0xC (required)   */
    exi_pvt_t max_power;           /* EVSEMaximumPowerLimit @+0x14 (optional)    */
    uint8_t   max_power_present;
    exi_pvt_t max_voltage;         /* EVSEMaximumVoltageLimit @+0x20 (required)  */
    exi_pvt_t min_current;         /* EVSEMinimumCurrentLimit @+0x28 (required)  */
    exi_pvt_t min_voltage;         /* EVSEMinimumVoltageLimit @+0x30 (required)  */
    exi_pvt_t opt_limit;           /* optional PVT @+0x38                        */
    uint8_t   opt_limit_present;
    exi_pvt_t peak_current;        /* PVT @+0x44 (required)                      */
    exi_pvt_t energy;              /* EVSEMaximumEnergyLimit? @+0x4C (optional)  */
    uint8_t   energy_present;
} din_dc_charge_param_t;
int din_dc_charge_param_decode(exi_stream_t *s, din_dc_charge_param_t *out);

/* Req encoders (full DIN document; choice per exi.h DIN_REQ_*). */
int din_sessionsetup_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                                const uint8_t *evccid, uint16_t evccid_len);
int din_servicediscovery_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len);
int din_cpd_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                       const din_meas_t *m, uint8_t ev_ready, uint8_t soc);
int din_cablecheck_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                              uint8_t ev_ready, uint8_t soc);
int din_precharge_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                             const din_meas_t *m, uint8_t ev_ready, uint8_t soc);
int din_powerdelivery_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                                 uint8_t charge_progress);
int din_welding_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len,
                           uint8_t ev_ready, uint8_t soc);
int din_sessionstop_req_encode(uint8_t *buf, uint16_t cap, const uint8_t *sid, uint16_t sid_len);

/* CurrentDemandReq grammar encoder (ev11 0x0806BDDC, full field list analyze101 Group I): DIN
 * framing (choice 0x0D) + DC_EVStatus + EVTargetCurrent PVT@0x14 + optional EVMaximumPower/Current/
 * VoltageLimit PVTs (gates 0x24/0x30/0x3C) + BulkChargingComplete@0x40 (gate 0x44) + ChargingComplete
 * @0x48 + optional RemainingTimeToFullSOC/ToBulkSOC (gates 0x54/0x60) + EVTargetVoltage PVT@0x64.
 * Writes the full document into buf[cap] (8-byte V2GTP reserved); returns length or EXI error. */
int din_cd_req_encode_exi(din_meas_t *m, uint8_t *buf, uint16_t cap,
                          const uint8_t *sid, uint16_t sid_len);

/* Res decoders (BODY after framing; leading 1-bit gates per analyze102). */
/* SessionSetupRes ev41 0x08062B1E (subev 0x1E): gate gate RC(5) gate EVSEID(len varlen + octets,
 * clamp 32) + optional EVSETimeStamp (2-bit choice; 8-byte fixed). */
int din_sessionsetup_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code,
                                    uint8_t *evseid, uint16_t *evseid_len);
/* ServiceDiscoveryRes ev3d 0x08063370 (subev 0x1A): RC(5) + ChargeServiceList + ServiceList +
 * optional EnergyTransferModeList. The replica extracts RC (session advancement) and structurally
 * consumes the lists [? full list sub-grammar partial]; the raw body is preserved by the writer. */
int din_servicediscovery_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code);
/* CPDRes ev0c 0x08065BFC (subev 0x08): RC(5) + processing flag(1)@body+1 + sched-choice(2) +
 * AC/DC-param choice(2); DIN -> DCparam ev15. `processing` = body[1] (1=ongoing). */
int din_cpd_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code,
                           uint8_t *processing, din_dc_charge_param_t *param);
/* PowerDeliveryRes ev2e 0x08063DBA (subev 0x14): gate gate RC(5) gate EVSEStatus-choice(2);
 * DIN choice 1 -> DC_EVSEStatus@+0x20. LINEAR (no list). */
int din_powerdelivery_res_decode_exi(const uint8_t *body, uint16_t len, uint8_t *response_code,
                                     din_dc_evse_status_t *status);
/* WeldingDetectionRes ev4f 0x08062754 (subev 0x22): gate gate RC(5) gate DC_EVSEStatus@+4 gate
 * EVSEPresentVoltage PVT@+0x10 -> meas.evse_present_voltage (+factor). */
int din_welding_res_decode_exi(const uint8_t *body, uint16_t len, din_meas_t *m,
                               uint8_t *response_code, din_dc_evse_status_t *status);

#endif /* DIN70121_H */