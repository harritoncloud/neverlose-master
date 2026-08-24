#pragma once

#include <cstddef>
#include <cstdint>

// Both BT paths load the shared 0.25f ratio at these instructions. The safe
// unlock redirects only their operands to a DLL-local 1.0f threshold while
// retaining the native classifier branches.
static constexpr std::uintptr_t BT_RATIO_LOAD_1 = 0x41334C93;
static constexpr std::uintptr_t BT_RATIO_LOAD_2 = 0x41346CB9;
static constexpr std::uintptr_t BT_RATIO_OPERAND_1 = BT_RATIO_LOAD_1 + 4;
static constexpr std::uintptr_t BT_RATIO_OPERAND_2 = BT_RATIO_LOAD_2 + 4;
static constexpr std::size_t BT_RATIO_LOAD_SIZE = 8;

// Legacy builds NOP-ed these JA instructions. They remain listed so the new
// transaction can validate and restore an old patched image safely.
static constexpr std::uintptr_t LERP1A_ADDR = 0x41334D89;
static constexpr std::uintptr_t LERP1B_ADDR = 0x41334D5C;
static constexpr std::uintptr_t LERP2A_ADDR = 0x41346DB5;
static constexpr std::uintptr_t LERP2B_ADDR = 0x41346D88;
static constexpr std::size_t LERP_NOP_LEN = 6;

bool apply_bt_ratio_unlock();
bool apply_lerp_disable();
