# acq/swd_dump.tcl — READ-ONLY STM32F4 flash acquisition (OpenOCD 0.12).
# Invoked by swd_dump.sh, which selects the CMSIS-DAP interface + stm32f4x target
# and connect-under-reset BEFORE this script runs.
#
# SAFETY: this script only READS. It never calls unlock / mass_erase / options_write
# / flash write. Reading flash cannot trigger a mass-erase; only an RDP 1->0 unlock
# write does that, and we never issue one. The probe gate below refuses to dump if
# the first words don't look like a sane vector table (RDP1/2 or bad connection).

init
reset halt
sleep 100

echo "==================== READ-ONLY ACQUISITION ===================="

# --- Option bytes (RDP / WRP / nBOOT / BOR). options_read does NOT modify them. ---
# NOTE: OpenOCD drives STM32F4 flash with the shared "stm32f2x" driver (see
# target/stm32f4x.cfg: flash bank ... stm32f2x). The command is stm32f2x, not stm32f4x.
if { [catch {stm32f2x options_read 0} e] } { echo "options_read: FAILED ($e)" }

# --- Device identity (confirms exact part, REPORT §8.1) ---
if { [catch {
    set idcode [lindex [read_memory 0xE0042000 32 1] 0]
    echo [format "DBGMCU_IDCODE = 0x%08x  (DEV_ID=0x%03x REV=0x%04x)" $idcode [expr {$idcode & 0xFFF}] [expr {($idcode >> 16) & 0xFFFF}]]
} e] } { echo "IDCODE read: FAILED ($e)" }
if { [catch {
    set uid [read_memory 0x1FFF7A10 32 3]
    echo [format "UID = 0x%08x 0x%08x 0x%08x" [lindex $uid 0] [lindex $uid 1] [lindex $uid 2]]
    set fsz [lindex [read_memory 0x1FFF7A22 16 1] 0]
    echo [format "FLASH_SIZE = %u KB (0x%04x)" $fsz $fsz]
} e] } { echo "UID/flash-size read: FAILED ($e)" }

# --- PROBE: first 8 bytes @ 0x08000000 must look like a Cortex-M vector table ---
set probe_ok 0
if { [catch {
    set v [read_memory 0x08000000 32 2]
    set sp [lindex $v 0]
    set rst [lindex $v 1]
    echo [format "PROBE: initial SP = 0x%08x   reset vector = 0x%08x" $sp $rst]
    set sp_ok [expr {($sp >= 0x20000000 && $sp <= 0x20030000) || ($sp >= 0x10000000 && $sp <= 0x10010000)}]
    set rst_ok [expr {($rst >= 0x08000001 && $rst < 0x08100000) && ($rst & 1)}]
    if { $sp_ok && $rst_ok } { set probe_ok 1 }
} e] } { echo "PROBE read FAILED ($e) -> RDP1/2 or no SWD connection." }

if { $probe_ok } {
    echo "PROBE OK: sane vector table -> likely RDP Level 0. Dumping (read-only)..."
    if { [catch {dump_image boot.bin 0x08000000 0x20000} e] } { echo "boot.bin FAILED: $e" } else { echo "boot.bin OK (0x20000 bytes)" }
    if { [catch {dump_image flash_full.bin 0x08000000 0x100000} e] } { echo "flash_full.bin FAILED: $e" } else { echo "flash_full.bin OK (0x100000 bytes)" }
    if { [catch {dump_image optbytes.bin 0x1FFFC000 0x20} e] } { echo "optbytes.bin FAILED: $e" } else { echo "optbytes.bin OK (0x20 bytes)" }
    if { [catch {dump_image uid.bin 0x1FFF7A10 0x14} e] } { echo "uid.bin FAILED: $e" } else { echo "uid.bin OK (0x14 bytes)" }
    echo "Dumps written to CWD. Verify: python3 acq/analyze_boot.py boot.bin"
} else {
    echo "PROBE FAILED: NOT a sane vector table. STOP — do NOT unlock / mass-erase."
    echo "  RDP1: read blocked (harmless). Use vendor BOOT_...UPG (REPORT §8.2b). NEVER unlock."
    echo "  RDP2: SWD permanently disabled. No dump possible."
}

echo "==================== done (target left halted) ===================="
shutdown
