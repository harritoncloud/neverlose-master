// ============================================================
//  fix_backtrack_lerp.cpp
//
//  Backtrack Lerp Fix — NOPs the lerp call at 0x4205A628.
//  This is a one-shot patch (no persist thread).
//
//  Corresponds to:
//    [Viera Utils] Applied Backtrack Lerp Fix
//    target -> 0x4205A628
//
//  WARNING: This address overlaps with nade prediction
//           interpolation. Enabling this breaks nade pred.
// ============================================================

#include "neverlose.h"
#include <cstdint>
#include <cstring>

#include "fix_backtrack_lerp.h"

// ---------------------------------------------------------------------------
// nop_region
// ---------------------------------------------------------------------------
static void nop_region(uintptr_t addr, size_t len)
{
    const auto* bytes = reinterpret_cast<volatile const uint8_t*>(addr);
    bool already_nopped = true;
    for (size_t index = 0; index < len; ++index)
    {
        if (bytes[index] != 0x90)
        {
            already_nopped = false;
            break;
        }
    }

    if (already_nopped)
        return;

    PVOID  base = reinterpret_cast<PVOID>(addr);
    SIZE_T sz   = len;
    DWORD  old  = 0;

    if (!NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(), &base, &sz, PAGE_EXECUTE_READWRITE, &old)))
        return;

    memset(reinterpret_cast<void*>(addr), 0x90, len);

    PVOID restore_base = reinterpret_cast<PVOID>(addr);
    SIZE_T restore_size = len;
    DWORD ignored = 0;
    NtProtectVirtualMemory(
        NtCurrentProcess(), &restore_base, &restore_size, old, &ignored);
    NtFlushInstructionCache(NtCurrentProcess(), reinterpret_cast<PVOID>(addr), len);
}

// ---------------------------------------------------------------------------
// apply_backtrack_lerp_fix
//   NOPs the 5-byte CALL at BT_LERP_TARGET_SLOT (0x4205A628).
// ---------------------------------------------------------------------------
void apply_backtrack_lerp_fix()
{
    nop_region(BT_LERP_TARGET_SLOT, 5);
}
