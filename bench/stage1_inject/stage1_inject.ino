/* stage1_inject.ino — Stage-1 signal injection for the Orientrise adapter bench (Arduino Mega 2560).
 *
 * Generates the injected signals the custom_fw bench console reads back (MEAS/CAN/NET/STM):
 *   - CP 1 kHz PWM, duty 0..1000 per-mille  -> pin 11 (OC1A/Timer1) -> 1k series -> adapter PD12.
 *   - 4 adjustable analog outputs (PWM + external RC filter + 3.3V-limiting divider):
 *       pin 9  -> PP   (adapter PA2 / ADC3 ch2)
 *       pin 10 -> CPD  (adapter PA0 / ADC3 ch0)
 *       pin 8  -> BAT  (adapter PC2 / ADC3 ch12)
 *       pin 7  -> HV sense low-V injection (into the HV divider input; see STAGE1_INJECTION.md)
 *
 * Serial @ 115200, line commands (CR/LF):
 *   C<duty>    CP duty per-mille 0..1000 (e.g. C500 = 50.0%, C50 = 5.0% digital mode)
 *   P<0..255>  PP analog PWM raw duty
 *   D<0..255>  CPD analog PWM raw duty
 *   B<0..255>  BAT analog PWM raw duty
 *   H<0..255>  HV sense PWM raw duty
 *   S          print current settings
 *
 * !!! SAFETY — READ FIRST !!!
 *  - The adapter ADC pins (PA0/PA1/PA2/PC2/PB0/PB1) are 3.3V-MAX, NOT 5V-tolerant in analog mode.
 *    EVERY analog output MUST pass a divider that caps it at <= 3.3V before touching the adapter.
 *    Recommended: 2k0 series + 3k3 to GND (ratio 0.623 -> 3.11V max from a 5V PWM), then 100nF to GND.
 *    Verify the pin voltage with a multimeter BEFORE connecting the adapter.
 *  - PD12 (CP) IS 5V-tolerant (FT); a 1k series resistor is still recommended.
 *  - HV side disconnected, bulk caps discharged. This is LOW-VOLTAGE signal injection only —
 *    it drives NO power stage. The adapter firmware is INERT (power drive gated).
 *  - Common GND between Mega and adapter bench ground.
 *
 * The analog PWM is ~490 Hz; the external RC filter averages it to DC. The exact voltage depends on
 * the divider + Vcc, so MEASURE the pin voltage and compare to the adapter MEAS mV readback — that
 * agreement is the fidelity check, not a nominal calculation.
 */

const int CP_PIN = 11;   /* OC1A / Timer1 — 1 kHz fast PWM */
const int PP_PIN = 9;    /* OC2B / Timer2 — analogWrite */
const int CPD_PIN = 10;  /* OC2A / Timer2 */
const int BAT_PIN = 8;   /* OC4C / Timer4 */
const int HV_PIN = 7;    /* OC4B / Timer4 */

static uint16_t cp_duty = 0;     /* per-mille */
static uint8_t pp_val = 0, cpd_val = 0, bat_val = 0, hv_val = 0;

static void cp_init(void)
{
    pinMode(CP_PIN, OUTPUT);
    /* Fast PWM mode 14 (TOP=ICR1), non-inverting OC1A, prescaler 8:
     * 16 MHz / 8 = 2 MHz (0.5 us/tick); ICR1=1999 -> 2000 ticks = 1000 us = 1 kHz.
     * Lands inside the adapter CP capture validity window CCR1 in [950,1050] us. */
    TCCR1A = 0;
    TCCR1B = 0;
    ICR1 = 1999;
    OCR1A = 0;
    TCCR1A = (1 << COM1A1) | (1 << WGM11);
    TCCR1B = (1 << WGM13) | (1 << WGM12) | (1 << CS11);
}

static void cp_set(uint16_t duty_permille)
{
    if (duty_permille > 1000) duty_permille = 1000;
    cp_duty = duty_permille;
    OCR1A = (uint16_t)((uint32_t)duty_permille * 2000u / 1000u);  /* 0..2000 */
}

static void print_status(void)
{
    Serial.print(F("CP duty=")); Serial.print(cp_duty); Serial.print(F(" permille (pin "));
    Serial.print(CP_PIN); Serial.println(F(")"));
    Serial.print(F("PP=")); Serial.print(pp_val);
    Serial.print(F(" CPD=")); Serial.print(cpd_val);
    Serial.print(F(" BAT=")); Serial.print(bat_val);
    Serial.print(F(" HV=")); Serial.println(hv_val);
}

void setup(void)
{
    Serial.begin(115200);
    cp_init();
    pinMode(PP_PIN, OUTPUT);
    pinMode(CPD_PIN, OUTPUT);
    pinMode(BAT_PIN, OUTPUT);
    pinMode(HV_PIN, OUTPUT);
    analogWrite(PP_PIN, 0);
    analogWrite(CPD_PIN, 0);
    analogWrite(BAT_PIN, 0);
    analogWrite(HV_PIN, 0);
    cp_set(0);
    Serial.println(F("stage1_inject ready. Cmds: C<duty> P/D/B/H<0..255> S"));
}

static char line[24];
static uint8_t line_len = 0;

static void handle_line(void)
{
    if (line_len == 0) return;
    line[line_len] = 0;
    char cmd = line[0];
    long v = strtol(line + 1, NULL, 10);
    switch (cmd) {
    case 'C': case 'c': cp_set((uint16_t)v); Serial.print(F("CP=")); Serial.println(cp_duty); break;
    case 'P': case 'p': pp_val = (uint8_t)constrain(v, 0, 255); analogWrite(PP_PIN, pp_val); Serial.print(F("PP=")); Serial.println(pp_val); break;
    case 'D': case 'd': cpd_val = (uint8_t)constrain(v, 0, 255); analogWrite(CPD_PIN, cpd_val); Serial.print(F("CPD=")); Serial.println(cpd_val); break;
    case 'B': case 'b': bat_val = (uint8_t)constrain(v, 0, 255); analogWrite(BAT_PIN, bat_val); Serial.print(F("BAT=")); Serial.println(bat_val); break;
    case 'H': case 'h': hv_val = (uint8_t)constrain(v, 0, 255); analogWrite(HV_PIN, hv_val); Serial.print(F("HV=")); Serial.println(hv_val); break;
    case 'S': case 's': print_status(); break;
    default: Serial.println(F("? cmds: C<duty> P/D/B/H<0..255> S")); break;
    }
    line_len = 0;
}

void loop(void)
{
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            handle_line();
        } else if (line_len < sizeof(line) - 1) {
            line[line_len++] = c;
        } else {
            line_len = 0;   /* overflow: drop */
        }
    }
}