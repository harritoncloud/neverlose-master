#include "fix_crouch_hitscan.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "neverlose.h"
#include "HookFn.h"
#include "crouch_hitscan_logic.h"

namespace
{
constexpr std::uintptr_t kBodyPointGenerator = 0x41490FA0;
constexpr std::uintptr_t kHeadPointGenerator = 0x414AC630;
constexpr std::size_t kLagRecordDuckAmountOffset = 0x98;
constexpr std::size_t kMaximumExistingPoints = 256;
constexpr std::size_t kMaximumGeneratedPoints = 32;

constexpr std::array<std::uint8_t, 16> kBodySignature = {
    0x55, 0x89, 0xE5, 0x53, 0x57, 0x56, 0x81, 0xEC,
    0x10, 0x01, 0x00, 0x00, 0x8B, 0x55, 0x08, 0xA1
};
constexpr std::array<std::uint8_t, 17> kHeadSignature = {
    0x55, 0x53, 0x57, 0x56, 0x81, 0xEC, 0x84, 0x01,
    0x00, 0x00, 0x8B, 0xBC, 0x24, 0x98, 0x01, 0x00,
    0x00
};

struct scan_point
{
    crouch_hitscan_logic::point3 position;
    std::uint8_t state[0x44];
};

struct scan_point_vector
{
    scan_point* begin;
    scan_point* end;
    scan_point* capacity;
};

static_assert(sizeof(void*) == 4);
static_assert(sizeof(scan_point) == 0x50);
static_assert(offsetof(scan_point_vector, end) == 0x04);
static_assert(offsetof(scan_point_vector, capacity) == 0x08);

using body_generator_fn = void(__cdecl*)(
    void*,
    void*,
    scan_point_vector*,
    const void*);
using head_generator_fn = void(__cdecl*)(
    void*,
    void*,
    scan_point_vector*,
    const void*,
    std::uint32_t);

void* g_body_trampoline = nullptr;
void* g_head_trampoline = nullptr;

template <std::size_t Size>
bool has_signature(
    std::uintptr_t address,
    const std::array<std::uint8_t, Size>& signature)
{
    if (!g_neverlose.in_range(reinterpret_cast<const void*>(address)) ||
        !g_neverlose.in_range(
            reinterpret_cast<const void*>(address + Size - 1)))
    {
        return false;
    }

    bool matches = false;
    __try
    {
        matches = std::memcmp(
            reinterpret_cast<const void*>(address),
            signature.data(),
            signature.size()) == 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        matches = false;
    }
    return matches;
}

bool point_count(const scan_point_vector* points, std::size_t& count)
{
    count = 0;
    if (!points)
        return false;

    bool valid = false;
    __try
    {
        const std::uintptr_t begin =
            reinterpret_cast<std::uintptr_t>(points->begin);
        const std::uintptr_t end =
            reinterpret_cast<std::uintptr_t>(points->end);
        const std::uintptr_t capacity =
            reinterpret_cast<std::uintptr_t>(points->capacity);
        if (begin == 0 || end == 0 || capacity == 0)
        {
            valid = begin == end && end == capacity;
        }
        else if (end >= begin &&
            capacity >= end &&
            (end - begin) % sizeof(scan_point) == 0 &&
            (capacity - begin) % sizeof(scan_point) == 0)
        {
            count = (end - begin) / sizeof(scan_point);
            valid = count <= kMaximumExistingPoints;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        valid = false;
    }
    return valid;
}

bool historical_duck_amount(void* context, float& duck_amount)
{
    if (reinterpret_cast<std::uintptr_t>(context) < 0x10000)
        return false;

    bool readable = false;
    __try
    {
        auto* record = *reinterpret_cast<std::uint8_t**>(
            static_cast<std::uint8_t*>(context) + sizeof(void*));
        if (reinterpret_cast<std::uintptr_t>(record) >= 0x10000)
        {
            std::memcpy(
                &duck_amount,
                record + kLagRecordDuckAmountOffset,
                sizeof(duck_amount));
            readable = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        readable = false;
    }
    return readable;
}

void contract_generated_points(
    scan_point_vector* points,
    std::size_t initial_count,
    float duck_amount,
    float full_crouch_scale)
{
    std::size_t final_count = 0;
    if (!point_count(points, final_count) ||
        final_count <= initial_count + 1 ||
        final_count - initial_count > kMaximumGeneratedPoints)
    {
        return;
    }

    const float scale = crouch_hitscan_logic::point_scale(
        duck_amount,
        full_crouch_scale);
    if (scale >= 1.0f)
        return;

    const crouch_hitscan_logic::point3 center =
        points->begin[initial_count].position;
    for (std::size_t index = initial_count + 1;
         index < final_count;
         ++index)
    {
        crouch_hitscan_logic::contract_toward_center(
            points->begin[index].position,
            center,
            scale);
    }
}

void __cdecl body_point_generator_hook(
    void* hitbox,
    void* context,
    scan_point_vector* points,
    const void* eye_position)
{
    std::size_t initial_count = 0;
    const bool valid_initial_shape = point_count(points, initial_count);

    reinterpret_cast<body_generator_fn>(g_body_trampoline)(
        hitbox,
        context,
        points,
        eye_position);

    float duck_amount = 0.0f;
    if (valid_initial_shape &&
        historical_duck_amount(context, duck_amount))
    {
        contract_generated_points(
            points,
            initial_count,
            duck_amount,
            crouch_hitscan_logic::kBodyPointScale);
    }
}

void __cdecl head_point_generator_hook(
    void* hitbox,
    void* context,
    scan_point_vector* points,
    const void* eye_position,
    std::uint32_t mode)
{
    std::size_t initial_count = 0;
    const bool valid_initial_shape = point_count(points, initial_count);

    reinterpret_cast<head_generator_fn>(g_head_trampoline)(
        hitbox,
        context,
        points,
        eye_position,
        mode);

    float duck_amount = 0.0f;
    if (valid_initial_shape &&
        historical_duck_amount(context, duck_amount))
    {
        contract_generated_points(
            points,
            initial_count,
            duck_amount,
            crouch_hitscan_logic::kHeadPointScale);
    }
}

bool install_body_hook()
{
    if (g_body_trampoline)
        return true;
    if (!has_signature(kBodyPointGenerator, kBodySignature))
        return false;

    const NTSTATUS status = HookFn(
        reinterpret_cast<void*>(kBodyPointGenerator),
        reinterpret_cast<void*>(&body_point_generator_hook),
        0,
        &g_body_trampoline);
    return NT_SUCCESS(status) && g_body_trampoline != nullptr;
}

bool install_head_hook()
{
    if (g_head_trampoline)
        return true;
    if (!has_signature(kHeadPointGenerator, kHeadSignature))
        return false;

    // Four one-byte pushes plus the six-byte stack allocation form the
    // complete 10-byte prologue copied into the trampoline.
    const NTSTATUS status = HookFn(
        reinterpret_cast<void*>(kHeadPointGenerator),
        reinterpret_cast<void*>(&head_point_generator_hook),
        5,
        &g_head_trampoline);
    return NT_SUCCESS(status) && g_head_trampoline != nullptr;
}

}

crouch_hitscan_status apply_crouch_hitscan_fix()
{
    crouch_hitscan_status status{};

    // Validate both targets before changing either function.
    if (!has_signature(kBodyPointGenerator, kBodySignature) ||
        !has_signature(kHeadPointGenerator, kHeadSignature))
    {
        return status;
    }

    status.body = install_body_hook();
    status.head = install_head_hook();
    return status;
}
