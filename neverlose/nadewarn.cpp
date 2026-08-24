// ============================================================
//  nadewarn.cpp
//
//  - Transparent backplate (skeet-style semi-transparent shadow)
//  - Make sharp edges to the warning.
//  - And Encompass
//  - Make progress bar thickness 1.35
// ============================================================

#define NOMINMAX
#define WIN32_NO_STATUS
#include <winsock2.h>
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <array>
#include <cstring>
#include <cstdint>

#include "fix_persist.h"
#include "neverlose.h"
#include "nadewarn.h"

// ---------------------------------------------------------------
// Backplate opacity
// The packed color is passed at [esp+0x14]. Its high byte is alpha,
// which the code cave clears for 100% transparency.
// ---------------------------------------------------------------
// NL supplies a 0..237.6-degree timer added to its original 150-degree
// start. Remap it to 135..405 degrees for an exact 270-degree arc.
static constexpr float NW_ARC_ORIGINAL_START = 2.61799383f;
static constexpr float NW_ARC_SOURCE_SPAN    = 4.14690256f;
static constexpr float NW_ARC_TARGET_SPAN    = 4.71238898f;
static constexpr float NW_ARC_SCALE_270      = NW_ARC_TARGET_SPAN / NW_ARC_SOURCE_SPAN;
static constexpr float NW_ARC_FIXED_ANGLE    = 2.35619449f;
static constexpr float NW_ARC_OUTER_RADIUS   = 29.7f;
static constexpr float NW_ARC_THICKNESS_VALUE = 1.35f;

// ---------------------------------------------------------------
// Byte tables
// ---------------------------------------------------------------
static const uint8_t ORIG_INDICATOR[] = {0xE8,0x5B,0x23,0x88,0x00};
static const uint8_t ORIG_OFFSCREEN[] = {0xE8,0x39,0x22,0x88,0x00};
static const uint8_t ORIG_TEXT[]      = {0xE8,0xC6,0x6A,0x01,0x00};
static const uint8_t ORIG_CAP_1[]     = {0xE8,0x8D,0xF2,0xFF,0xFF};
static const uint8_t ORIG_CAP_2[]     = {0xE8,0xC7,0xF1,0xFF,0xFF};
static const uint8_t ORIG_ARC_STORE[] = {0xF3,0x0F,0x11,0x44,0x24,0x0C};
static const uint8_t ORIG_THICKNESS[] = {0x67,0x66,0x9E,0x40};
static const uint8_t ORIG_ENDPOINT[]  = {0x36,0x8D,0x27,0x40};
static const uint8_t ORIG_RADIUS[]    = {0x99,0x99,0xDD,0x41};

static const uint8_t NOP_CAP[]        = {0x83,0xC4,0x14,0x90,0x90};
static const uint8_t NOP_TEXT[]       = {0x83,0xC4,0x04,0x90,0x90};

// ---------------------------------------------------------------
// Memory helpers
// ---------------------------------------------------------------
static bool nw_range_accessible(uintptr_t address, size_t size)
{
    if (!address || !size || address + size < address)
        return false;

    MEMORY_BASIC_INFORMATION information{};
    if (!VirtualQuery(
            reinterpret_cast<const void*>(address),
            &information,
            sizeof(information)) ||
        information.State != MEM_COMMIT ||
        (information.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
    {
        return false;
    }

    const uintptr_t region_begin =
        reinterpret_cast<uintptr_t>(information.BaseAddress);
    const uintptr_t region_end = region_begin + information.RegionSize;
    return address >= region_begin && address + size <= region_end;
}

static bool nw_bytes_equal(
    uintptr_t address,
    const uint8_t* expected,
    size_t size)
{
    if (!address || !expected || !size || address + size < address)
        return false;

    bool equal = false;
    __try
    {
        const auto* current =
            reinterpret_cast<volatile const uint8_t*>(address);
        equal = true;
        for (size_t i = 0; i < size; ++i)
        {
            if (current[i] != expected[i])
            {
                equal = false;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        equal = false;
    }

    return equal;
}

static bool nw_write_exact(
    uintptr_t address,
    const uint8_t* data,
    size_t size)
{
    if (!data || !nw_range_accessible(address, size))
        return false;

    DWORD old_protection = 0;
    if (!VirtualProtect(
            reinterpret_cast<void*>(address),
            size,
            PAGE_EXECUTE_READWRITE,
            &old_protection))
    {
        return false;
    }

    memcpy(reinterpret_cast<void*>(address), data, size);
    const BOOL flushed = FlushInstructionCache(
        GetCurrentProcess(),
        reinterpret_cast<void*>(address),
        size);

    DWORD ignored_protection = 0;
    const BOOL restored = VirtualProtect(
        reinterpret_cast<void*>(address),
        size,
        old_protection,
        &ignored_protection);

    return flushed && restored && nw_bytes_equal(address, data, size);
}

static bool nw_seal_code(void* address, size_t size)
{
    DWORD old = 0;
    return VirtualProtect(address, size, PAGE_EXECUTE_READ, &old) &&
        FlushInstructionCache(GetCurrentProcess(), address, size);
}

// ---------------------------------------------------------------
// Transparent backplate code cave
//
// Instead of NOPing the backplate draw calls, redirect them through
// a code cave that scales the alpha byte in the packed color.
//
// The onscreen texture is 66x78: its bottom 12 pixels form the pin
// tail. Crop both the destination rectangle and UV range to 66x66 so
// the image is not stretched, then apply a 33-pixel rounded mask to
// remove the antialiased transition left at the bottom edge.
//
// Stack layout at the call site (8 dwords pushed, 0x20 bytes):
//   [esp+0x00] = arg1 (texture/handle)
//   [esp+0x04] = arg2 (vertex ptr [esi+0x110])
//   [esp+0x08] = arg3 (vertex ptr [esi+0x90])
//   [esp+0x0C] = arg4 (vertex ptr [esi+0x70])
//   [esp+0x10] = arg5 (esi base)
//   [esp+0x14] = arg6 (ebx, packed ABGR color)
//   [esp+0x18] = arg7 (0x00)
//   [esp+0x1C] = arg8 (0x0F corner mask)
//
// fn_texture_draw is stdcall (callee cleans up 0x20 bytes via ret 0x20).
// ---------------------------------------------------------------
static void* g_backplate_cave = nullptr;
static uint8_t g_jmp_indicator[5] = {};
static uint8_t g_jmp_offscreen[5] = {};
static uint8_t g_jmp_arc[6] = {};
static volatile LONG g_nadewarn_started = 0;
static HANDLE g_nadewarn_thread = nullptr;
static HANDLE g_nadewarn_stop_event = nullptr;

static constexpr size_t NW_PATCH_COUNT = 9;
static constexpr size_t NW_MAX_PATCH_SIZE = 8;

struct NwPatch
{
    uintptr_t address;
    const uint8_t* original;
    const uint8_t* replacement;
    const uint8_t* alternate_original;
    size_t size;
    uintptr_t instruction_address;
    size_t instruction_size;
};

enum class NwPatchState
{
    replacement,
    recoverable_original,
    unknown
};

static std::array<NwPatch, NW_PATCH_COUNT> g_nw_patches{};
static size_t g_nw_patch_count = 0;

static bool nw_backplate_prepare()
{
    // Build code caves on first call
    if (g_backplate_cave)
        return true;

    constexpr size_t BACKPLATE_CAVE_SIZE = 256;
    g_backplate_cave = VirtualAlloc(
        nullptr,
        BACKPLATE_CAVE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!g_backplate_cave)
        return false;

    const uintptr_t base = reinterpret_cast<uintptr_t>(g_backplate_cave);
    uint8_t* p = reinterpret_cast<uint8_t*>(base);
    size_t pos = 0;

    auto emit_cave = [&](uintptr_t return_address, bool crop_to_square) {
        const uintptr_t cave = base + pos;

        if (crop_to_square) {
            // p_max.y = p_min.y + (p_max.x - p_min.x)
            // uv_max.y = width / original_height
            static const uint8_t crop_square[] = {
                0x8B, 0x44, 0x24, 0x04,       // mov eax, [esp+0x04] ; p_min
                0x8B, 0x54, 0x24, 0x08,       // mov edx, [esp+0x08] ; p_max
                0xF3, 0x0F, 0x10, 0x02,       // movss xmm0, [edx]
                0xF3, 0x0F, 0x5C, 0x00,       // subss xmm0, [eax]
                0xF3, 0x0F, 0x10, 0x4A, 0x04, // movss xmm1, [edx+0x04]
                0xF3, 0x0F, 0x5C, 0x48, 0x04, // subss xmm1, [eax+0x04]
                0x0F, 0x28, 0xD0,             // movaps xmm2, xmm0
                0xF3, 0x0F, 0x5E, 0xD1,       // divss xmm2, xmm1
                0xF3, 0x0F, 0x58, 0x40, 0x04, // addss xmm0, [eax+0x04]
                0xF3, 0x0F, 0x11, 0x42, 0x04, // movss [edx+0x04], xmm0
                0x8B, 0x44, 0x24, 0x10,       // mov eax, [esp+0x10] ; uv_max
                0xF3, 0x0F, 0x11, 0x50, 0x04, // movss [eax+0x04], xmm2
                0xC7, 0x44, 0x24, 0x18,
                0x00, 0x00, 0x04, 0x42        // mov dword [esp+0x18], 33.0f
            };
            memcpy(p + pos, crop_square, sizeof(crop_square));
            pos += sizeof(crop_square);
        }

        // Clear the high alpha byte, preserving RGB.
        static const uint8_t alpha0[] = {
            0x8B, 0x44, 0x24, 0x14,       // mov eax, [esp+0x14]
            0x25, 0xFF, 0xFF, 0xFF, 0x00, // and eax, 0x00FFFFFF
            0x89, 0x44, 0x24, 0x14        // mov [esp+0x14], eax
        };
        memcpy(p + pos, alpha0, sizeof(alpha0));
        pos += sizeof(alpha0);

        p[pos++] = 0xE8;
        uint32_t rel_call = static_cast<uint32_t>(NW_FN_TEXTURE_DRAW)
                          - static_cast<uint32_t>(base + pos + 4);
        memcpy(p + pos, &rel_call, 4);
        pos += 4;

        p[pos++] = 0xE9;
        uint32_t rel_ret = static_cast<uint32_t>(return_address)
                         - static_cast<uint32_t>(base + pos + 4);
        memcpy(p + pos, &rel_ret, 4);
        pos += 4;

        return cave;
    };

    const uintptr_t cave1 = emit_cave(NW_INDICATOR_CALL + 5, true);
    const uintptr_t cave2 = emit_cave(NW_OFFSCREEN_BACKPLATE + 5, false);

    // Build JMP patches for call sites
    g_jmp_indicator[0] = 0xE9;
    uint32_t jrel1 = static_cast<uint32_t>(cave1)
                   - static_cast<uint32_t>(NW_INDICATOR_CALL + 5);
    memcpy(g_jmp_indicator + 1, &jrel1, 4);

    g_jmp_offscreen[0] = 0xE9;
    uint32_t jrel2 = static_cast<uint32_t>(cave2)
                   - static_cast<uint32_t>(NW_OFFSCREEN_BACKPLATE + 5);
    memcpy(g_jmp_offscreen + 1, &jrel2, 4);

    if (pos > BACKPLATE_CAVE_SIZE ||
        !nw_seal_code(g_backplate_cave, BACKPLATE_CAVE_SIZE))
    {
        VirtualFree(g_backplate_cave, 0, MEM_RELEASE);
        g_backplate_cave = nullptr;
        memset(g_jmp_indicator, 0, sizeof(g_jmp_indicator));
        memset(g_jmp_offscreen, 0, sizeof(g_jmp_offscreen));
        return false;
    }

    return true;
}

// ---------------------------------------------------------------
// 270-degree timer arc
// ---------------------------------------------------------------
static void* g_arc270 = nullptr;

static bool nw_arc270_prepare()
{
    if (g_arc270)
        return true;

    constexpr size_t ARC_CAVE_SIZE = 128;
    g_arc270 = VirtualAlloc(
        nullptr,
        ARC_CAVE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!g_arc270)
        return false;

    const uintptr_t base  = reinterpret_cast<uintptr_t>(g_arc270);
    uint8_t* p            = reinterpret_cast<uint8_t*>(base);
    size_t   pos          = 0;

    const size_t OFF_MIN = 48;
    const size_t OFF_SCL = 52;
    const size_t OFF_FIXED = 56;
    const uint32_t a_min = static_cast<uint32_t>(base + OFF_MIN);
    const uint32_t a_scl = static_cast<uint32_t>(base + OFF_SCL);
    const uint32_t a_fixed = static_cast<uint32_t>(base + OFF_FIXED);

    p[pos++]=0xF3; p[pos++]=0x0F; p[pos++]=0x5C; p[pos++]=0x05;
    memcpy(p+pos, &a_min, 4); pos+=4;

    p[pos++]=0xF3; p[pos++]=0x0F; p[pos++]=0x59; p[pos++]=0x05;
    memcpy(p+pos, &a_scl, 4); pos+=4;

    p[pos++]=0xF3; p[pos++]=0x0F; p[pos++]=0x58; p[pos++]=0x05;
    memcpy(p+pos, &a_fixed, 4); pos+=4;

    p[pos++]=0xF3; p[pos++]=0x0F; p[pos++]=0x11;
    p[pos++]=0x44; p[pos++]=0x24; p[pos++]=0x0C;

    p[pos++] = 0xE9;
    uint32_t rel = static_cast<uint32_t>(NW_ARC_STORE + 6)
                 - static_cast<uint32_t>(base + pos + 4);
    memcpy(p+pos, &rel, 4); pos+=4;

    float arc_min = NW_ARC_ORIGINAL_START;
    float arc_scl = NW_ARC_SCALE_270;
    float arc_fixed = NW_ARC_FIXED_ANGLE;
    memcpy(p + OFF_MIN, &arc_min, 4);
    memcpy(p + OFF_SCL, &arc_scl, 4);
    memcpy(p + OFF_FIXED, &arc_fixed, 4);

    g_jmp_arc[0] = 0xE9;
    rel = static_cast<uint32_t>(base)
        - static_cast<uint32_t>(NW_ARC_STORE + 5);
    memcpy(g_jmp_arc + 1, &rel, 4);
    g_jmp_arc[5] = 0x90;

    if (pos > OFF_MIN ||
        OFF_FIXED + sizeof(float) > ARC_CAVE_SIZE ||
        !nw_seal_code(g_arc270, ARC_CAVE_SIZE))
    {
        VirtualFree(g_arc270, 0, MEM_RELEASE);
        g_arc270 = nullptr;
        memset(g_jmp_arc, 0, sizeof(g_jmp_arc));
        return false;
    }

    return true;
}

static bool nw_prepare_patch_set()
{
    if (g_nw_patch_count == NW_PATCH_COUNT)
        return true;

    if (!nw_backplate_prepare() || !nw_arc270_prepare())
        return false;

    g_nw_patches = {{
        {
            NW_INDICATOR_CALL,
            ORIG_INDICATOR,
            g_jmp_indicator,
            nullptr,
            sizeof(ORIG_INDICATOR),
            NW_INDICATOR_CALL,
            sizeof(ORIG_INDICATOR)
        },
        {
            NW_OFFSCREEN_BACKPLATE,
            ORIG_OFFSCREEN,
            g_jmp_offscreen,
            nullptr,
            sizeof(ORIG_OFFSCREEN),
            NW_OFFSCREEN_BACKPLATE,
            sizeof(ORIG_OFFSCREEN)
        },
        {
            NW_TEXT_CALL,
            ORIG_TEXT,
            ORIG_TEXT,
            NOP_TEXT,
            sizeof(ORIG_TEXT),
            NW_TEXT_CALL,
            sizeof(ORIG_TEXT)
        },
        {
            NW_ARC_CAP_1,
            ORIG_CAP_1,
            NOP_CAP,
            nullptr,
            sizeof(ORIG_CAP_1),
            NW_ARC_CAP_1,
            sizeof(ORIG_CAP_1)
        },
        {
            NW_ARC_CAP_2,
            ORIG_CAP_2,
            NOP_CAP,
            nullptr,
            sizeof(ORIG_CAP_2),
            NW_ARC_CAP_2,
            sizeof(ORIG_CAP_2)
        },
        {
            NW_ARC_STORE,
            ORIG_ARC_STORE,
            g_jmp_arc,
            nullptr,
            sizeof(ORIG_ARC_STORE),
            NW_ARC_STORE,
            sizeof(ORIG_ARC_STORE)
        },
        {
            NW_ARC_THICKNESS,
            ORIG_THICKNESS,
            reinterpret_cast<const uint8_t*>(&NW_ARC_THICKNESS_VALUE),
            nullptr,
            sizeof(ORIG_THICKNESS),
            NW_ARC_THICKNESS - 4,
            8
        },
        {
            NW_ARC_FIXED_ENDPOINT,
            ORIG_ENDPOINT,
            reinterpret_cast<const uint8_t*>(&NW_ARC_FIXED_ANGLE),
            nullptr,
            sizeof(ORIG_ENDPOINT),
            NW_ARC_FIXED_ENDPOINT - 4,
            8
        },
        {
            NW_ARC_RADIUS,
            ORIG_RADIUS,
            reinterpret_cast<const uint8_t*>(&NW_ARC_OUTER_RADIUS),
            nullptr,
            sizeof(ORIG_RADIUS),
            NW_ARC_RADIUS - 4,
            8
        }
    }};
    g_nw_patch_count = g_nw_patches.size();
    return true;
}

static NwPatchState nw_patch_state(const NwPatch& patch)
{
    if (nw_bytes_equal(patch.address, patch.replacement, patch.size))
        return NwPatchState::replacement;

    if (nw_bytes_equal(patch.address, patch.original, patch.size) ||
        (patch.alternate_original &&
         nw_bytes_equal(
             patch.address,
             patch.alternate_original,
             patch.size)))
    {
        return NwPatchState::recoverable_original;
    }

    return NwPatchState::unknown;
}

static bool nw_build_repair_plan(
    std::array<bool, NW_PATCH_COUNT>& repair,
    bool& needs_repair)
{
    repair.fill(false);
    needs_repair = false;

    if (g_nw_patch_count != NW_PATCH_COUNT)
        return false;

    for (size_t i = 0; i < g_nw_patch_count; ++i)
    {
        const NwPatchState state = nw_patch_state(g_nw_patches[i]);
        if (state == NwPatchState::unknown)
            return false;

        if (state == NwPatchState::recoverable_original)
        {
            repair[i] = true;
            needs_repair = true;
        }
    }

    return true;
}

class NwThreadFreeze
{
public:
    NwThreadFreeze() = default;
    NwThreadFreeze(const NwThreadFreeze&) = delete;
    NwThreadFreeze& operator=(const NwThreadFreeze&) = delete;

    ~NwThreadFreeze()
    {
        thaw_patch_threads(state_);
    }

    bool freeze()
    {
        return freeze_patch_threads(state_);
    }

    bool safe_for(
        const std::array<bool, NW_PATCH_COUNT>& repair) const
    {
        std::array<patch_code_range, NW_PATCH_COUNT> ranges{};
        size_t range_count = 0;
        for (size_t i = 0; i < g_nw_patch_count; ++i)
        {
            if (!repair[i])
                continue;

            const NwPatch& patch = g_nw_patches[i];
            ranges[range_count++] = {
                patch.instruction_address,
                patch.instruction_size
            };
        }

        return patch_threads_are_safe(
            state_,
            ranges.data(),
            range_count);
    }

private:
    patch_thread_freeze_state state_{};
};

class NwPatchWriteLock
{
public:
    NwPatchWriteLock()
    {
        acquire_patch_write_lock();
    }

    NwPatchWriteLock(const NwPatchWriteLock&) = delete;
    NwPatchWriteLock& operator=(const NwPatchWriteLock&) = delete;

    ~NwPatchWriteLock()
    {
        release_patch_write_lock();
    }
};

static bool nw_copy_current(
    const NwPatch& patch,
    std::array<uint8_t, NW_MAX_PATCH_SIZE>& destination)
{
    if (patch.size > destination.size() ||
        !nw_range_accessible(patch.address, patch.size))
    {
        return false;
    }

    const auto* current =
        reinterpret_cast<volatile const uint8_t*>(patch.address);
    for (size_t i = 0; i < patch.size; ++i)
        destination[i] = current[i];
    return true;
}

static bool nw_rollback(
    const std::array<bool, NW_PATCH_COUNT>& attempted,
    const std::array<
        std::array<uint8_t, NW_MAX_PATCH_SIZE>,
        NW_PATCH_COUNT>& previous)
{
    bool restored = true;
    for (size_t index = g_nw_patch_count; index > 0; --index)
    {
        const size_t i = index - 1;
        if (!attempted[i])
            continue;

        const NwPatch& patch = g_nw_patches[i];
        if (!nw_write_exact(
                patch.address,
                previous[i].data(),
                patch.size))
        {
            restored = false;
        }
    }

    return restored;
}

static bool nw_apply_patch_set(bool freeze_other_threads)
{
    NwPatchWriteLock patch_lock;

    std::array<bool, NW_PATCH_COUNT> repair{};
    bool needs_repair = false;
    if (!nw_build_repair_plan(repair, needs_repair))
        return false;
    if (!needs_repair)
        return true;

    NwThreadFreeze thread_freeze;
    if (freeze_other_threads)
    {
        if (!thread_freeze.freeze())
            return false;

        if (!nw_build_repair_plan(repair, needs_repair) ||
            !thread_freeze.safe_for(repair))
        {
            return false;
        }
        if (!needs_repair)
            return true;
    }

    std::array<bool, NW_PATCH_COUNT> attempted{};
    std::array<
        std::array<uint8_t, NW_MAX_PATCH_SIZE>,
        NW_PATCH_COUNT> previous{};

    for (size_t i = 0; i < g_nw_patch_count; ++i)
    {
        if (!repair[i])
            continue;

        const NwPatch& patch = g_nw_patches[i];
        if (!nw_copy_current(patch, previous[i]))
        {
            nw_rollback(attempted, previous);
            return false;
        }

        attempted[i] = true;
        if (!nw_write_exact(
                patch.address,
                patch.replacement,
                patch.size))
        {
            nw_rollback(attempted, previous);
            return false;
        }
    }

    for (size_t i = 0; i < g_nw_patch_count; ++i)
    {
        if (nw_patch_state(g_nw_patches[i]) !=
            NwPatchState::replacement)
        {
            nw_rollback(attempted, previous);
            return false;
        }
    }

    return true;
}

static bool nw_patch_set_needs_repair(bool& needs_repair)
{
    std::array<bool, NW_PATCH_COUNT> repair{};
    return nw_build_repair_plan(repair, needs_repair);
}

// ---------------------------------------------------------------
// Persist thread
// ---------------------------------------------------------------
static DWORD WINAPI nw_thread(PVOID parameter)
{
    const HANDLE stop_event = static_cast<HANDLE>(parameter);

    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT)
        return 0;

    for (;;)
    {
        bool needs_repair = false;
        if (nw_patch_set_needs_repair(needs_repair) && needs_repair)
            nw_apply_patch_set(true);

        if (WaitForSingleObject(stop_event, 50) != WAIT_TIMEOUT)
            break;
    }

    return 0;
}

// ---------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------
void setup_nadewarn()
{
    if (InterlockedCompareExchange(&g_nadewarn_started, 1, 0) != 0)
        return;

    // setup_hooks runs before the mapped Neverlose entry point. Install the
    // complete visual patch set now, while none of its code can be executing.
    if (!nw_prepare_patch_set() || !nw_apply_patch_set(false))
    {
        InterlockedExchange(&g_nadewarn_started, 0);
        return;
    }

    g_nadewarn_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_nadewarn_stop_event)
    {
        InterlockedExchange(&g_nadewarn_started, 0);
        return;
    }

    g_nadewarn_thread = CreateThread(
        nullptr, 0, nw_thread, g_nadewarn_stop_event, 0, nullptr);
    if (!g_nadewarn_thread)
    {
        CloseHandle(g_nadewarn_stop_event);
        g_nadewarn_stop_event = nullptr;
        InterlockedExchange(&g_nadewarn_started, 0);
    }
}

void request_nadewarn_stop()
{
    const HANDLE stop_event = g_nadewarn_stop_event;
    if (stop_event)
        SetEvent(stop_event);
}
