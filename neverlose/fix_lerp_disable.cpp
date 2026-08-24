#include "neverlose.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "fix_lerp_disable.h"
#include "fix_persist.h"

namespace
{
constexpr std::uintptr_t kBuildBase = 0x412A0000;
constexpr std::size_t kMaximumSiteSize = BT_RATIO_LOAD_SIZE;
alignas(4) const float kSafeRatioThreshold = 1.0f;

enum class site_kind : std::uint8_t
{
    ratio_load,
    legacy_branch
};

using byte_buffer = std::array<std::uint8_t, kMaximumSiteSize>;

struct patch_site
{
    std::uintptr_t address;
    std::size_t size;
    site_kind kind;
    byte_buffer original;
    byte_buffer compatible;
    bool has_compatible;
};

constexpr std::array<patch_site, 6> kSites = {{
    {
        BT_RATIO_LOAD_1,
        BT_RATIO_LOAD_SIZE,
        site_kind::ratio_load,
        {0xF3, 0x0F, 0x10, 0x05, 0xF4, 0xCD, 0x06, 0x42},
        {},
        false
    },
    {
        BT_RATIO_LOAD_2,
        BT_RATIO_LOAD_SIZE,
        site_kind::ratio_load,
        {0xF3, 0x0F, 0x10, 0x05, 0xF4, 0xCD, 0x06, 0x42},
        {},
        false
    },
    {
        LERP1B_ADDR,
        LERP_NOP_LEN,
        site_kind::legacy_branch,
        {0x0F, 0x87, 0x76, 0xFF, 0xFF, 0xFF},
        {0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
        true
    },
    {
        LERP1A_ADDR,
        LERP_NOP_LEN,
        site_kind::legacy_branch,
        {0x0F, 0x87, 0x49, 0xFF, 0xFF, 0xFF},
        {0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
        true
    },
    {
        LERP2B_ADDR,
        LERP_NOP_LEN,
        site_kind::legacy_branch,
        {0x0F, 0x87, 0x76, 0xFF, 0xFF, 0xFF},
        {0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
        true
    },
    {
        LERP2A_ADDR,
        LERP_NOP_LEN,
        site_kind::legacy_branch,
        {0x0F, 0x87, 0x49, 0xFF, 0xFF, 0xFF},
        {0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
        true
    }
}};

constexpr std::array<patch_code_range, kSites.size()> kRanges = {{
    {BT_RATIO_LOAD_1, BT_RATIO_LOAD_SIZE},
    {BT_RATIO_LOAD_2, BT_RATIO_LOAD_SIZE},
    {LERP1B_ADDR, LERP_NOP_LEN},
    {LERP1A_ADDR, LERP_NOP_LEN},
    {LERP2B_ADDR, LERP_NOP_LEN},
    {LERP2A_ADDR, LERP_NOP_LEN}
}};

std::array<byte_buffer, kSites.size()> g_previous{};
std::array<bool, kSites.size()> g_changed{};
volatile LONG g_installed = 0;
volatile LONG g_conflicted = 0;
volatile LONG g_transaction_ok = 0;

bool query_image_range(std::uintptr_t address, std::size_t size)
{
    if (!address || !size)
        return false;

    MEMORY_BASIC_INFORMATION information{};
    if (VirtualQuery(
            reinterpret_cast<const void*>(address),
            &information,
            sizeof(information)) != sizeof(information))
    {
        return false;
    }

    const std::uintptr_t begin =
        reinterpret_cast<std::uintptr_t>(information.BaseAddress);
    const std::uintptr_t end = begin + information.RegionSize;
    const std::uintptr_t requested_end = address + size;
    return information.State == MEM_COMMIT &&
        (information.Protect & PAGE_GUARD) == 0 &&
        (information.Protect & 0xFF) != PAGE_NOACCESS &&
        information.AllocationBase == reinterpret_cast<void*>(kBuildBase) &&
        end >= begin && requested_end >= address &&
        address >= begin && requested_end <= end;
}

byte_buffer desired_bytes(const patch_site& site)
{
    byte_buffer desired = site.original;
    if (site.kind == site_kind::ratio_load)
    {
        static_assert(sizeof(void*) == sizeof(std::uint32_t));
        const std::uint32_t threshold_address = static_cast<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(&kSafeRatioThreshold));
        std::memcpy(
            desired.data() + 4,
            &threshold_address,
            sizeof(threshold_address));
    }
    return desired;
}

bool read_site(const patch_site& site, byte_buffer& bytes)
{
    if (!query_image_range(site.address, site.size))
        return false;

    __try
    {
        std::memcpy(
            bytes.data(),
            reinterpret_cast<const void*>(site.address),
            site.size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

bool matches(
    const byte_buffer& left,
    const byte_buffer& right,
    std::size_t size)
{
    return std::memcmp(left.data(), right.data(), size) == 0;
}

bool known_state(const patch_site& site, const byte_buffer& current)
{
    const byte_buffer desired = desired_bytes(site);
    return matches(current, desired, site.size) ||
        matches(current, site.original, site.size) ||
        (site.has_compatible &&
            matches(current, site.compatible, site.size));
}

bool write_site(const patch_site& site, const byte_buffer& bytes)
{
    DWORD old_protection = 0;
    if (!VirtualProtect(
            reinterpret_cast<void*>(site.address),
            site.size,
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
            site.size);
        copied = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        copied = false;
    }

    DWORD ignored = 0;
    const bool restored = VirtualProtect(
        reinterpret_cast<void*>(site.address),
        site.size,
        old_protection,
        &ignored) != FALSE;
    const bool flushed = FlushInstructionCache(
        GetCurrentProcess(),
        reinterpret_cast<const void*>(site.address),
        site.size) != FALSE;

    byte_buffer current{};
    return copied && restored && flushed &&
        read_site(site, current) && matches(current, bytes, site.size);
}

bool validate_sites(bool* needs_write)
{
    bool pending = false;
    for (const patch_site& site : kSites)
    {
        byte_buffer current{};
        if (!read_site(site, current) || !known_state(site, current))
            return false;

        const byte_buffer desired = desired_bytes(site);
        if (!matches(current, desired, site.size))
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
        if (!read_site(kSites[index], g_previous[index]) ||
            !known_state(kSites[index], g_previous[index]))
        {
            return;
        }
    }

    for (std::size_t index = 0; index < kSites.size(); ++index)
    {
        const patch_site& site = kSites[index];
        const byte_buffer desired = desired_bytes(site);
        if (matches(g_previous[index], desired, site.size))
            continue;

        g_changed[index] = true;
        if (!write_site(site, desired))
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

void persist_bt_ratio_unlock()
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

bool apply_bt_ratio_unlock()
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
    register_persist_callback(persist_bt_ratio_unlock);
    return true;
}

bool apply_lerp_disable()
{
    return apply_bt_ratio_unlock();
}
