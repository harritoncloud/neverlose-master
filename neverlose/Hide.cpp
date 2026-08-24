#include "neverlose.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "Hide.h"
#include "fix_persist.h"

namespace
{
    using HidePatch = patch_code_range;

    constexpr HidePatch kHidePatches[] = {
        { 0x4151B37E, 5 },
        { 0x4151B4DE, 5 },
        { 0x4151B53B, 5 },
        { 0x4151B698, 5 },
        { 0x4151B6F2, 5 },
        { 0x4151B8BA, 5 },
        { 0x4151B915, 5 },
        { 0x4151BA4F, 5 },
        { 0x4151BAAC, 5 },
        { 0x4151BD6F, 5 },
        { 0x41606BCD, 5 },
        { 0x41605B77, 4 },
        { 0x41606F3C, 5 },
        { 0x41606D28, 5 },
        { 0x41606DE6, 5 },
        { 0x41606E7C, 5 },
    };

    bool is_nopped(const HidePatch& patch)
    {
        const auto* bytes =
            reinterpret_cast<volatile const uint8_t*>(patch.address);

        for (size_t index = 0; index < patch.size; ++index)
        {
            if (bytes[index] != 0x90)
                return false;
        }

        return true;
    }

    void apply_patch(const HidePatch& patch)
    {
        if (is_nopped(patch))
            return;

        PVOID base = reinterpret_cast<PVOID>(patch.address);
        SIZE_T size = patch.size;
        DWORD old_protection = 0;

        if (!NT_SUCCESS(NtProtectVirtualMemory(
            NtCurrentProcess(),
            &base,
            &size,
            PAGE_EXECUTE_READWRITE,
            &old_protection
        )))
            return;

        std::memset(
            reinterpret_cast<void*>(patch.address),
            0x90,
            patch.size
        );

        PVOID restore_base = reinterpret_cast<PVOID>(patch.address);
        SIZE_T restore_size = patch.size;
        DWORD ignored = 0;
        NtProtectVirtualMemory(
            NtCurrentProcess(),
            &restore_base,
            &restore_size,
            old_protection,
            &ignored
        );
        NtFlushInstructionCache(
            NtCurrentProcess(),
            reinterpret_cast<PVOID>(patch.address),
            patch.size
        );
    }

    void apply_all()
    {
        for (const HidePatch& patch : kHidePatches)
            apply_patch(patch);
    }

    void Hide_persist_callback()
    {
        bool dirty = false;
        for (const HidePatch& patch : kHidePatches)
        {
            if (!is_nopped(patch))
            {
                dirty = true;
                break;
            }
        }

        if (!dirty)
            return;

        run_persist_patch_transaction_locked(
            kHidePatches,
            sizeof(kHidePatches) / sizeof(kHidePatches[0]),
            apply_all);
    }
}

void apply_Hide()
{
    apply_all();
    register_persist_callback(Hide_persist_callback);
}
