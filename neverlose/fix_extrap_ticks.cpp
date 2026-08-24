// ============================================================
//  fix_extrap_ticks.cpp
//
//  Keeps EXTRAP_LIMIT_ADDR at the native two-tick budget.
//  Persist via unified watchdog (check-before-write).
//
//  extrap_limit @ 0x413F9EC2  (1 byte)
// ============================================================

#include "neverlose.h"
#include <cstdint>

#include "fix_extrap_ticks.h"
#include "fix_persist.h"

// ---------------------------------------------------------------------------
// patch_byte
// ---------------------------------------------------------------------------
static void patch_byte(uintptr_t addr, uint8_t val)
{
    if (*reinterpret_cast<volatile uint8_t*>(addr) == val)
        return;

    PVOID  base = reinterpret_cast<PVOID>(addr);
    SIZE_T sz   = sizeof(val);
    DWORD  old  = 0;

    if (!NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), &base, &sz, PAGE_EXECUTE_READWRITE, &old)))
        return;

    *reinterpret_cast<uint8_t*>(addr) = val;

    PVOID restore_base = reinterpret_cast<PVOID>(addr);
    SIZE_T restore_size = sizeof(val);
    DWORD ignored = 0;
    NtProtectVirtualMemory(
        NtCurrentProcess(), &restore_base, &restore_size, old, &ignored);
    NtFlushInstructionCache(NtCurrentProcess(), reinterpret_cast<PVOID>(addr), sizeof(val));
}

// ---------------------------------------------------------------------------
// persist callback — registered with unified watchdog
// ---------------------------------------------------------------------------
static void extrap_persist_cb()
{
    if (*reinterpret_cast<volatile uint8_t*>(EXTRAP_LIMIT_ADDR) != EXTRAP_TICK_COUNT)
        patch_byte(EXTRAP_LIMIT_ADDR, EXTRAP_TICK_COUNT);
}

// ---------------------------------------------------------------------------
// apply_extrap_ticks_fix
// ---------------------------------------------------------------------------
void apply_extrap_ticks_fix()
{
    patch_byte(EXTRAP_LIMIT_ADDR, EXTRAP_TICK_COUNT);

    register_persist_callback(extrap_persist_cb);
}
