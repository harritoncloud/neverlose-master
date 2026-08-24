#pragma once

// ============================================================
//  fix_backtrack_lerp.h
//
//  Backtrack Lerp Fix — patches the BT lerp call site.
//  Corresponds to: [Viera Utils] Applied Backtrack Lerp Fix
//                  target -> 0x4205A628
//
//  WARNING: This address is shared with nade prediction
//           interpolation. Calling this WILL break nade pred.
//           Only enable if you don't need nade prediction.
// ============================================================

static constexpr uintptr_t BT_LERP_TARGET_SLOT = 0x4205A628;

void apply_backtrack_lerp_fix();
