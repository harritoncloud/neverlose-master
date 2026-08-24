#pragma once

#include <cmath>

namespace crouch_hitscan_logic
{
constexpr float kCrouchBlendStart = 0.55f;
constexpr float kCrouchBlendEnd = 0.90f;
constexpr float kMinimumDuckAmount = -0.01f;
constexpr float kMaximumDuckAmount = 1.01f;
constexpr float kBodyPointScale = 0.82f;
constexpr float kHeadPointScale = 0.88f;

struct point3
{
    float x;
    float y;
    float z;
};

inline bool finite_point(const point3& point)
{
    return std::isfinite(point.x) &&
        std::isfinite(point.y) &&
        std::isfinite(point.z);
}

inline float crouch_blend(float duck_amount)
{
    if (!std::isfinite(duck_amount) ||
        duck_amount < kMinimumDuckAmount ||
        duck_amount > kMaximumDuckAmount ||
        duck_amount <= kCrouchBlendStart)
    {
        return 0.0f;
    }
    if (duck_amount >= kCrouchBlendEnd)
        return 1.0f;

    return (duck_amount - kCrouchBlendStart) /
        (kCrouchBlendEnd - kCrouchBlendStart);
}

inline float point_scale(float duck_amount, float full_crouch_scale)
{
    if (!std::isfinite(full_crouch_scale) ||
        full_crouch_scale <= 0.0f ||
        full_crouch_scale > 1.0f)
    {
        return 1.0f;
    }

    const float blend = crouch_blend(duck_amount);
    return 1.0f - blend * (1.0f - full_crouch_scale);
}

inline bool contract_toward_center(
    point3& point,
    const point3& center,
    float scale)
{
    if (!finite_point(point) ||
        !finite_point(center) ||
        !std::isfinite(scale) ||
        scale <= 0.0f ||
        scale >= 1.0f)
    {
        return false;
    }

    point.x = center.x + (point.x - center.x) * scale;
    point.y = center.y + (point.y - center.y) * scale;
    point.z = center.z + (point.z - center.z) * scale;
    return true;
}
}
