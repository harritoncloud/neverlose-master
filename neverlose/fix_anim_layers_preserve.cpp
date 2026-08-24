#include "neverlose.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "HookFn.h"
#include "fix_anim_layers_preserve.h"
#include "fix_persist.h"

namespace
{
constexpr uintptr_t kDispatchSite = 0x41B73AA6;
constexpr std::uint8_t kOriginalDispatch[] = {
    0xFF, 0xA0, 0x80, 0x03, 0x00, 0x00
};
constexpr patch_code_range kDispatchPatchRange = {
    kDispatchSite,
    sizeof(kOriginalDispatch)
};

constexpr std::size_t kAnimationOverlayOffset = 0x2990;
constexpr std::size_t kAnimationOverlayCountOffset = 0x299C;
constexpr std::size_t kMinimumAnimationLayerCount = 12;
constexpr std::size_t kLayer10WeightOffset = 0x250;
constexpr std::size_t kLayer10CycleOffset = 0x25C;
constexpr std::size_t kLayer10OwnerOffset = 0x260;
constexpr std::size_t kLayer11WeightOffset = 0x288;
constexpr std::size_t kLayer11CycleOffset = 0x294;
constexpr std::size_t kLayer11OwnerOffset = 0x298;

using animation_update_fn = void(__thiscall*)(void*);

struct layer_snapshot
{
    std::uint8_t* layers = nullptr;
    void* owner = nullptr;
    std::uint32_t layer10_weight = 0;
    std::uint32_t layer10_cycle = 0;
    std::uint32_t layer11_weight = 0;
    std::uint32_t layer11_cycle = 0;
};

bool normalized_layer_value(std::uint32_t bits)
{
    if ((bits & 0x7F800000u) == 0x7F800000u)
        return false;

    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value >= -0.001f && value <= 1.001f;
}

bool capture_layers(void* entity, layer_snapshot& snapshot)
{
    if (reinterpret_cast<std::uintptr_t>(entity) < 0x10000)
        return false;

    __try
    {
        auto* entity_bytes = static_cast<std::uint8_t*>(entity);
        auto* layers = *reinterpret_cast<std::uint8_t* volatile*>(
            entity_bytes + kAnimationOverlayOffset);
        if (!layers ||
            *reinterpret_cast<volatile const std::uint32_t*>(
                entity_bytes + kAnimationOverlayCountOffset) <
                kMinimumAnimationLayerCount ||
            *reinterpret_cast<void* volatile*>(
                layers + kLayer10OwnerOffset) != entity ||
            *reinterpret_cast<void* volatile*>(
                layers + kLayer11OwnerOffset) != entity)
        {
            return false;
        }

        snapshot.layers = layers;
        snapshot.owner = entity;
        snapshot.layer10_weight =
            *reinterpret_cast<volatile const std::uint32_t*>(
                layers + kLayer10WeightOffset);
        snapshot.layer10_cycle =
            *reinterpret_cast<volatile const std::uint32_t*>(
                layers + kLayer10CycleOffset);
        snapshot.layer11_weight =
            *reinterpret_cast<volatile const std::uint32_t*>(
                layers + kLayer11WeightOffset);
        snapshot.layer11_cycle =
            *reinterpret_cast<volatile const std::uint32_t*>(
                layers + kLayer11CycleOffset);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

void repair_value(std::uint8_t* layers, std::size_t offset, std::uint32_t saved)
{
    auto* value = reinterpret_cast<volatile std::uint32_t*>(layers + offset);
    if (!normalized_layer_value(*value) && normalized_layer_value(saved))
        *value = saved;
}

void repair_invalid_layers(const layer_snapshot& snapshot)
{
    if (!snapshot.layers || !snapshot.owner)
        return;

    __try
    {
        auto* entity_bytes = static_cast<std::uint8_t*>(snapshot.owner);
        if (*reinterpret_cast<std::uint8_t* volatile*>(
                entity_bytes + kAnimationOverlayOffset) != snapshot.layers ||
            *reinterpret_cast<void* volatile*>(
                snapshot.layers + kLayer10OwnerOffset) != snapshot.owner ||
            *reinterpret_cast<void* volatile*>(
                snapshot.layers + kLayer11OwnerOffset) != snapshot.owner)
        {
            return;
        }

        repair_value(
            snapshot.layers,
            kLayer10WeightOffset,
            snapshot.layer10_weight);
        repair_value(
            snapshot.layers,
            kLayer10CycleOffset,
            snapshot.layer10_cycle);
        repair_value(
            snapshot.layers,
            kLayer11WeightOffset,
            snapshot.layer11_weight);
        repair_value(
            snapshot.layers,
            kLayer11CycleOffset,
            snapshot.layer11_cycle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

extern "C" __declspec(noinline) void __fastcall
anim_layers_sanitize_update(void* entity, animation_update_fn update)
{
    layer_snapshot snapshot{};
    const bool captured = capture_layers(entity, snapshot);
    update(entity);
    if (captured)
        repair_invalid_layers(snapshot);
}

__declspec(naked) void anim_layers_preserve_hook()
{
    __asm
    {
        mov edx, dword ptr [eax + 380h]
        test edx, edx
        jz passthrough

        cmp dword ptr [edx + 5], 0BE80F18Bh
        jne passthrough
        cmp word ptr [edx + 0Eh], 3674h
        jne passthrough

        jmp anim_layers_sanitize_update

    passthrough:
        jmp edx
    }
}

bool has_original_dispatch()
{
    const auto* current =
        reinterpret_cast<volatile const std::uint8_t*>(kDispatchSite);

    for (std::size_t i = 0; i < sizeof(kOriginalDispatch); ++i)
    {
        if (current[i] != kOriginalDispatch[i])
            return false;
    }

    return true;
}

bool has_our_dispatch_hook()
{
    const auto* current =
        reinterpret_cast<volatile const std::uint8_t*>(kDispatchSite);

    if (current[0] != 0xE9 || current[5] != 0x90)
        return false;

    const auto displacement =
        *reinterpret_cast<volatile const std::int32_t*>(kDispatchSite + 1);
    const auto destination =
        static_cast<std::uint32_t>(kDispatchSite + 5) +
        static_cast<std::uint32_t>(displacement);

    return destination ==
        static_cast<std::uint32_t>(
            reinterpret_cast<uintptr_t>(&anim_layers_preserve_hook));
}

void install_anim_layers_hook()
{
    if (has_our_dispatch_hook() || !has_original_dispatch())
        return;

    HookFn(
        reinterpret_cast<void*>(kDispatchSite),
        reinterpret_cast<void*>(&anim_layers_preserve_hook),
        1);
}

void persist_anim_layers_hook()
{
    if (has_our_dispatch_hook() || !has_original_dispatch())
        return;

    run_persist_patch_transaction_locked(
        &kDispatchPatchRange,
        1,
        install_anim_layers_hook);
}
}

void apply_anim_layers_preserve()
{
    install_anim_layers_hook();
    register_persist_callback(persist_anim_layers_hook);
}
