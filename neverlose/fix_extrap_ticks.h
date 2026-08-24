#pragma once

// ============================================================
//  fix_extrap_ticks.h
//
//  Restores the native dynamic extrapolation tick budget.
//  Patch:
//    extrap_limit @ 0x413F9EC2  (1 byte)
// ============================================================

static constexpr uintptr_t EXTRAP_LIMIT_ADDR = 0x413F9EC2;
static constexpr uint8_t   EXTRAP_TICK_COUNT = 2; // 31.25 ms at 64 Hz

void apply_extrap_ticks_fix();
