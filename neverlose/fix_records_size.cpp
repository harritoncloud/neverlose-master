#include "neverlose.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "fix_persist.h"
#include "fix_records_size.h"

namespace
{
constexpr std::size_t kSiteSize = 9;

struct compare_site
{
    std::uintptr_t address;
    std::array<std::uint8_t, kSiteSize> original;
    std::array<std::uint8_t, kSiteSize> desired;
};

constexpr std::array<compare_site, 2> kSites = {{
    {
        RECWIN_COMPARE_1,
        {0x83, 0xF8, RECWIN_NATIVE_SIZE, 0x0F, 0x82, 0xD5, 0x00, 0x00, 0x00},
        {0x83, 0xF8, RECWIN_SIZE,        0x0F, 0x82, 0xD5, 0x00, 0x00, 0x00}
    },
    {
        RECWIN_COMPARE_2,
        {0x83, 0xF8, RECWIN_NATIVE_SIZE, 0x0F, 0x82, 0xAA, 0xEF, 0xFF, 0xFF},
        {0x83, 0xF8, RECWIN_SIZE,        0x0F, 0x82, 0xAA, 0xEF, 0xFF, 0xFF}
    }
}};

constexpr std::array<patch_code_range, kSites.size()> kRanges = {{
    {RECWIN_COMPARE_1, kSiteSize},
    {RECWIN_COMPARE_2, kSiteSize}
}};

std::array<std::array<std::uint8_t, kSiteSize>, kSites.size()> g_previous{};
std::array<bool, kSites.size()> g_changed{};
volatile LONG g_installed = 0;
volatile LONG g_conflicted = 0;
volatile LONG g_transaction_ok = 0;

bool read_site(
    const compare_site& site,
    std::array<std::uint8_t, kSiteSize>& bytes)
{
    __try
    {
        std::memcpy(
            bytes.data(),
            reinterpret_cast<const void*>(site.address),
            bytes.size());
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

bool matches(
    const std::array<std::uint8_t, kSiteSize>& left,
    const std::array<std::uint8_t, kSiteSize>& right)
{
    return std::memcmp(left.data(), right.data(), left.size()) == 0;
}

bool write_site(
    const compare_site& site,
    const std::array<std::uint8_t, kSiteSize>& bytes)
{
    DWORD old_protection = 0;
    if (!VirtualProtect(
            reinterpret_cast<void*>(site.address),
            bytes.size(),
            PAGE_EXECUTE_READWRITE,
            &old_protection))
    {
        return false;
    }

    bool copied = false;
    __try
    {
        std::memcpy(
            reinterpret_cast<void*>(site.address),
            bytes.data(),
            bytes.size());
        copied = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        copied = false;
    }

    DWORD ignored = 0;
    const bool restored = VirtualProtect(
        reinterpret_cast<void*>(site.address),
        bytes.size(),
        old_protection,
        &ignored) != FALSE;
    const bool flushed = FlushInstructionCache(
        GetCurrentProcess(),
        reinterpret_cast<const void*>(site.address),
        bytes.size()) != FALSE;

    std::array<std::uint8_t, kSiteSize> current{};
    return copied && restored && flushed &&
        read_site(site, current) && matches(current, bytes);
}

bool validate_sites(bool* needs_write)
{
    bool pending = false;
    for (const compare_site& site : kSites)
    {
        std::array<std::uint8_t, kSiteSize> current{};
        if (!read_site(site, current) ||
            (!matches(current, site.original) &&
                !matches(current, site.desired)))
        {
            return false;
        }

        if (!matches(current, site.desired))
            pending = true;
    }

    if (needs_write)
        *needs_write = pending;
    return true;
}

void rollback(std::size_t attempted)
{
    for (std::size_t index = attempted; index > 0; --index)
    {
        const std::size_t site_index = index - 1;
        if (g_changed[site_index])
            write_site(kSites[site_index], g_previous[site_index]);
    }
}

void transaction_writer()
{
    InterlockedExchange(&g_transaction_ok, 0);
    g_changed.fill(false);

    for (std::size_t index = 0; index < kSites.size(); ++index)
    {
        const compare_site& site = kSites[index];
        if (!read_site(site, g_previous[index]) ||
            (!matches(g_previous[index], site.original) &&
                !matches(g_previous[index], site.desired)))
        {
            return;
        }
    }

    for (std::size_t index = 0; index < kSites.size(); ++index)
    {
        if (matches(g_previous[index], kSites[index].desired))
            continue;

        g_changed[index] = true;
        if (!write_site(kSites[index], kSites[index].desired))
        {
            rollback(index + 1);
            return;
        }
    }

    InterlockedExchange(&g_transaction_ok, 1);
}

bool run_transaction()
{
    InterlockedExchange(&g_transaction_ok, 0);
    if (!run_persist_patch_transaction_locked(
            kRanges.data(),
            kRanges.size(),
            transaction_writer))
    {
        return false;
    }

    return InterlockedCompareExchange(
        &g_transaction_ok,
        0,
        0) != 0;
}

void persist_records_size()
{
    if (InterlockedCompareExchange(&g_installed, 0, 0) == 0 ||
        InterlockedCompareExchange(&g_conflicted, 0, 0) != 0)
        return;

    bool needs_write = false;
    if (!validate_sites(&needs_write))
    {
        InterlockedExchange(&g_conflicted, 1);
        return;
    }

    if (needs_write && !run_transaction())
        InterlockedExchange(&g_conflicted, 1);
}
}

bool apply_records_size_fix()
{
    bool needs_write = false;
    if (!validate_sites(&needs_write))
        return false;

    bool applied = true;
    if (needs_write)
    {
        acquire_patch_write_lock();
        applied = run_transaction();
        release_patch_write_lock();
    }
    if (!applied)
        return false;

    InterlockedExchange(&g_installed, 1);
    register_persist_callback(persist_records_size);
    return true;
}
