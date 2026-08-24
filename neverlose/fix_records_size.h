#pragma once

#include <cstdint>

// The two paths measure a vector of 4-byte history entries in bytes. Keeping
// 0x14 preserves the existing five-sample BT unlock without claiming that the
// immediate directly allocates twenty lag-record slots.
static constexpr std::uintptr_t RECWIN_COMPARE_1 = 0x413349F8;
static constexpr std::uintptr_t RECWIN_COMPARE_2 = 0x41341F18;
static constexpr std::uintptr_t RECWIN_HITS_1 = RECWIN_COMPARE_1 + 2;
static constexpr std::uintptr_t RECWIN_HITS_2 = RECWIN_COMPARE_2 + 2;
static constexpr std::uint8_t RECWIN_NATIVE_SIZE = 0x08;
static constexpr std::uint8_t RECWIN_SIZE = 0x14;

bool apply_records_size_fix();
