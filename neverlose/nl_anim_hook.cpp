#include "nl_anim_hook.h"

#include "neverlose.h"
#include "HookFn.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{
constexpr std::uint8_t kTargetSignature[] = {
    0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x53, 0x56,
    0x8B, 0x75, 0x08, 0x57, 0x8B, 0x86, 0x98, 0x2D,
    0x00, 0x00, 0x80, 0x78, 0x05, 0x00, 0x74, 0x0D,
    0x80, 0xBE, 0x8D, 0x2D, 0x00, 0x00, 0x00, 0x75,
    0x04, 0xB3, 0x01, 0xEB, 0x02, 0x32, 0xDB
};

constexpr std::uintptr_t kExpectedTargetRva = 0xCB2F10;
constexpr std::size_t kPatchTailBytes = 1;
constexpr std::uint32_t kLogEvery = 60;

constexpr std::size_t kOverlayBaseOffset = 0x2980;
constexpr std::size_t kOverlayLayerStride = 0x60;
constexpr std::size_t kLayerCycleSnapshotOffset = 0x2C;
constexpr std::size_t kLayerWeightSnapshotOffset = 0x30;

using target_fn = void(__cdecl*)(
    void*,
    std::uint32_t,
    std::uint32_t);

void* g_original_trampoline = nullptr;
std::atomic<std::uint32_t> g_hook_fire_count{0};
bool g_trace_enabled = false;

struct signature_result
{
    std::uint8_t* address;
    std::size_t matches;
};

struct anim_hook_sample
{
    float layer10_cycle;
    float layer10_weight;
    float layer11_cycle;
    float layer11_weight;
};

signature_result find_unique_target()
{
    auto* const begin =
        static_cast<const std::uint8_t*>(g_neverlose.base());
    const std::size_t image_size = g_neverlose.size();
    if (!begin || image_size < sizeof(kTargetSignature))
        return {};

    const auto* const last =
        begin + image_size - sizeof(kTargetSignature);
    const std::uint8_t* cursor = begin;
    const std::uint8_t* match = nullptr;
    std::size_t match_count = 0;

    while (cursor <= last)
    {
        const std::size_t searchable =
            static_cast<std::size_t>(last - cursor) + 1;
        const auto* candidate = static_cast<const std::uint8_t*>(
            std::memchr(cursor, kTargetSignature[0], searchable));
        if (!candidate)
            break;

        if (std::memcmp(
                candidate,
                kTargetSignature,
                sizeof(kTargetSignature)) == 0)
        {
            match = candidate;
            ++match_count;
        }
        cursor = candidate + 1;
    }

    return {
        const_cast<std::uint8_t*>(match),
        match_count
    };
}

bool read_sample(const void* context, anim_hook_sample* sample)
{
    if (!context || !sample)
        return false;

    const auto* const base = static_cast<const std::uint8_t*>(context);
    const std::size_t layer10 =
        kOverlayBaseOffset + 10 * kOverlayLayerStride;
    const std::size_t layer11 =
        kOverlayBaseOffset + 11 * kOverlayLayerStride;

    __try
    {
        std::memcpy(
            &sample->layer10_cycle,
            base + layer10 + kLayerCycleSnapshotOffset,
            sizeof(float));
        std::memcpy(
            &sample->layer10_weight,
            base + layer10 + kLayerWeightSnapshotOffset,
            sizeof(float));
        std::memcpy(
            &sample->layer11_cycle,
            base + layer11 + kLayerCycleSnapshotOffset,
            sizeof(float));
        std::memcpy(
            &sample->layer11_weight,
            base + layer11 + kLayerWeightSnapshotOffset,
            sizeof(float));
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

void trace_sample(
    std::uint32_t fire_count,
    void* context,
    std::uint32_t first,
    std::uint32_t second)
{
    if (!IsDebuggerPresent())
        return;

    anim_hook_sample sample{};
    if (!read_sample(context, &sample))
        return;

    char message[320] = {};
    const int length = _snprintf_s(
        message,
        sizeof(message),
        _TRUNCATE,
        "nl_anim_hook fire #%lu context=%p arg1=0x%08lX arg2=0x%08lX "
        "L10(cyc=%.3f,w=%.3f) L11(cyc=%.3f,w=%.3f)\n",
        static_cast<unsigned long>(fire_count),
        context,
        static_cast<unsigned long>(first),
        static_cast<unsigned long>(second),
        sample.layer10_cycle,
        sample.layer10_weight,
        sample.layer11_cycle,
        sample.layer11_weight);
    if (length > 0)
        OutputDebugStringA(message);
}

void __cdecl nl_anim_hook(
    void* context,
    std::uint32_t first,
    std::uint32_t second)
{
    if (g_trace_enabled)
    {
        const std::uint32_t fire_count =
            g_hook_fire_count.fetch_add(1, std::memory_order_relaxed);
        if (context && fire_count % kLogEvery == 0)
            trace_sample(fire_count, context, first, second);
    }

    const auto original =
        reinterpret_cast<target_fn>(g_original_trampoline);
    if (original)
        original(context, first, second);
}
}

bool install_nl_anim_hook()
{
    auto logger = ENTER_LOGGER(g_neverlose.logman);
    const signature_result result = find_unique_target();
    if (result.matches != 1 || !result.address)
    {
        logger << "[HOOK] nl_anim_hook signature count: "
               << result.matches << ". Hook skipped.\n";
        OutputDebugStringA(
            "nl_anim_hook: unique target signature not found; skipped\n");
        return false;
    }

    auto* const expected =
        static_cast<std::uint8_t*>(g_neverlose.base()) +
        kExpectedTargetRva;
    if (result.address != expected)
    {
        logger << "[HOOK] nl_anim_hook target RVA mismatch. Hook skipped.\n";
        OutputDebugStringA(
            "nl_anim_hook: target RVA mismatch; skipped\n");
        return false;
    }

    // Tracing is diagnostic-only. Publish the mode before installing the
    // detour so normal gameplay avoids an atomic increment on every call.
    g_trace_enabled = IsDebuggerPresent() != FALSE;

    const NTSTATUS status = HookFn(
        result.address,
        reinterpret_cast<void*>(&nl_anim_hook),
        kPatchTailBytes,
        &g_original_trampoline);
    if (!NT_SUCCESS(status) || !g_original_trampoline)
    {
        logger << "[HOOK] nl_anim_hook detour failed: 0x"
               << std::hex << status << ".\n";
        OutputDebugStringA("nl_anim_hook: detour installation failed\n");
        return false;
    }

    logger << "[HOOK] nl_anim_hook inspection detour installed at 0x"
           << std::hex
           << reinterpret_cast<std::uintptr_t>(result.address)
           << ".\n";
    OutputDebugStringA("nl_anim_hook: inspection detour installed\n");
    return true;
}
