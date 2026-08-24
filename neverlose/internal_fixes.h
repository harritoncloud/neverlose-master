#ifndef NEVERLOSE_INTERNAL_FIXES_H
#define NEVERLOSE_INTERNAL_FIXES_H

void fix_mem_dispatcher();
void fix_sha256();
void hijack_requestor();
void install_crypto_capture();

// Backtrack history unlocks
bool apply_records_size_fix();
bool apply_bt_ratio_unlock();
bool apply_lerp_disable();
void apply_extrap_ticks_fix();
void apply_hitscan_fix();

#endif // NEVERLOSE_INTERNAL_FIXES_H
