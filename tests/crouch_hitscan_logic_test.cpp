#include <cmath>
#include <cstdio>
#include <limits>

#include "../neverlose/crouch_hitscan_logic.h"

namespace
{
bool near(float left, float right)
{
    return std::fabs(left - right) < 0.0001f;
}

bool expect(bool condition, const char* message)
{
    if (condition)
        return true;

    std::printf("FAIL: %s\n", message);
    return false;
}
}

int main()
{
    using namespace crouch_hitscan_logic;

    bool ok = true;
    ok = expect(
        near(point_scale(0.55f, kBodyPointScale), 1.0f),
        "standing and low-duck records stay unchanged") && ok;
    ok = expect(
        near(point_scale(0.90f, kBodyPointScale), kBodyPointScale),
        "full crouch reaches the body limit") && ok;
    ok = expect(
        near(point_scale(0.725f, kBodyPointScale), 0.91f),
        "crouch transition blends continuously") && ok;
    ok = expect(
        near(
            point_scale(
                std::numeric_limits<float>::quiet_NaN(),
                kBodyPointScale),
            1.0f),
        "invalid duck amount fails closed") && ok;
    ok = expect(
        near(point_scale(2.0f, kBodyPointScale), 1.0f),
        "out-of-range duck amount fails closed") && ok;
    ok = expect(
        point_scale(1.0f, kHeadPointScale) >
            point_scale(1.0f, kBodyPointScale),
        "head correction remains more conservative") && ok;

    const point3 center{10.0f, 10.0f, 10.0f};
    point3 edge{20.0f, 0.0f, 15.0f};
    ok = expect(
        contract_toward_center(edge, center, kBodyPointScale),
        "valid edge point is contracted") && ok;
    ok = expect(
        near(edge.x, 18.2f) &&
            near(edge.y, 1.8f) &&
            near(edge.z, 14.1f),
        "edge point moves toward center on all axes") && ok;

    point3 invalid{std::numeric_limits<float>::infinity(), 0.0f, 0.0f};
    ok = expect(
        !contract_toward_center(invalid, center, kBodyPointScale),
        "invalid point is not modified") && ok;

    if (!ok)
        return 1;

    std::puts("PASS: crouch hitscan point contraction");
    return 0;
}
