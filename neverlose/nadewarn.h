#pragma once

// ============================================================
//  nadewarn.h
// ============================================================

// Drop shadow below icon (teardrop/pin shape)
static constexpr uintptr_t NW_INDICATOR_CALL      = 0x413D68B0;

// Offscreen shadow backplate
static constexpr uintptr_t NW_OFFSCREEN_BACKPLATE = 0x413D69D2;

// Text call (for Molotov/HE toggle)
static constexpr uintptr_t NW_TEXT_CALL           = 0x413D6CC5;

// Arc rounded cap calls
static constexpr uintptr_t NW_ARC_CAP_1           = 0x41C56C9E;
static constexpr uintptr_t NW_ARC_CAP_2           = 0x41C56D64;

// Arc360 encompass hook
static constexpr uintptr_t NW_ARC_STORE           = 0x413D713C;

// Arc float params
static constexpr uintptr_t NW_ARC_THICKNESS       = 0x413D714F;
static constexpr uintptr_t NW_ARC_FIXED_ENDPOINT  = 0x413D7157;
static constexpr uintptr_t NW_ARC_RADIUS          = 0x413D715F;

// Texture draw function (target of indicator/offscreen calls)
static constexpr uintptr_t NW_FN_TEXTURE_DRAW     = 0x41C58C10;

void setup_nadewarn();
void request_nadewarn_stop();
