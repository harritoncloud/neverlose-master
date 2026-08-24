#include "neverlose.h"

#include <cstdint>

#include "HideLegit.h"
#include "fix_persist.h"

namespace
{
    constexpr uintptr_t kLegitVisibilitySlot = 0x4205BC78;
    constexpr LONG kOriginalVisibilityCallback = 0x41BB9E90;
    constexpr LONG kHiddenVisibilityCallback = 0x412A53B0;

    void hide_legit_if_supported()
    {
        auto* slot = reinterpret_cast<volatile LONG*>(kLegitVisibilitySlot);
        const LONG current = *slot;

        if (current == kHiddenVisibilityCallback ||
            current != kOriginalVisibilityCallback)
        {
            return;
        }

        PVOID base = reinterpret_cast<PVOID>(kLegitVisibilitySlot);
        SIZE_T size = sizeof(LONG);
        DWORD old_protection = 0;
        const NTSTATUS status = NtProtectVirtualMemory(
            NtCurrentProcess(),
            &base,
            &size,
            PAGE_READWRITE,
            &old_protection
        );

        if (status < 0)
            return;

        InterlockedCompareExchange(
            slot,
            kHiddenVisibilityCallback,
            kOriginalVisibilityCallback
        );

        PVOID restore_base = reinterpret_cast<PVOID>(kLegitVisibilitySlot);
        SIZE_T restore_size = sizeof(LONG);
        DWORD ignored_protection = 0;
        NtProtectVirtualMemory(
            NtCurrentProcess(),
            &restore_base,
            &restore_size,
            old_protection,
            &ignored_protection
        );
    }
}

void apply_HideLegit()
{
    hide_legit_if_supported();
    register_persist_callback(hide_legit_if_supported);
}
