#include <array>
#include <cstdint>
#include <cstdio>

#include "../../neverlose/fix_extrap_ticks.h"
#include "../../neverlose/rage_record_logic.h"

static_assert(EXTRAP_TICK_COUNT == 2);

namespace
{
struct test_record
{
    std::uint32_t simulation_bits;
    bool valid;
};

test_record* select_record(
    const rage_record_logic::ring_view<test_record>& ring,
    std::uint32_t shot_bits,
    std::uint32_t maximum_pairs)
{
    return rage_record_logic::find_shot_record(
        ring,
        shot_bits,
        maximum_pairs,
        [](const test_record* record)
        {
            return record->simulation_bits;
        },
        [](const test_record* record)
        {
            return record->valid;
        });
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
    test_record newest{0x40800000u, true}; // 4.0f
    test_record second{0x40400000u, true}; // 3.0f
    test_record third{0x40000000u, true};  // 2.0f
    test_record oldest{0x3F800000u, true}; // 1.0f

    std::array<test_record*, 8> storage{};
    storage[6] = &newest;
    storage[7] = &second;
    storage[0] = &third;
    storage[1] = &oldest;

    rage_record_logic::ring_view<test_record> ring{
        storage.data(),
        static_cast<std::uint32_t>(storage.size()),
        14,
        4
    };

    bool ok = true;
    ok = expect(
        rage_record_logic::choose_extended_tick_delta(
            3, 2, true, false, false, 4) == 3,
        "unclassified BT warmup keeps requested tick") && ok;
    ok = expect(
        rage_record_logic::choose_extended_tick_delta(
            4, 3, true, true, true, 4) == 4,
        "pending BT classification keeps requested tick") && ok;
    ok = expect(
        rage_record_logic::choose_extended_tick_delta(
            4, 3, true, true, false, 4) == 3,
        "mature BT state keeps valid native adjustment") && ok;
    ok = expect(
        rage_record_logic::choose_extended_tick_delta(
            2, -1, true, true, false, 4) == 2,
        "invalid mature adjustment is clamped to requested tick") && ok;
    ok = expect(
        rage_record_logic::choose_extended_tick_delta(
            2, 3, true, true, false, 4) == 2,
        "forward mature adjustment is rejected") && ok;
    ok = expect(
        rage_record_logic::choose_extended_tick_delta(
            5, 4, true, false, false, 4) == 4,
        "outside extended window remains native") && ok;
    ok = expect(
        rage_record_logic::choose_extended_tick_delta(
            -1, -2, true, false, false, 4) == -2,
        "negative request remains native") && ok;
    ok = expect(
        rage_record_logic::choose_extended_tick_delta(
            3, 2, false, false, false, 4) == 2,
        "unreadable BT state fails closed") && ok;
    ok = expect(
        rage_record_logic::should_retry_original_tick(4, 3, 3, 4),
        "exact native one-tick correction enables lookup retry") && ok;
    ok = expect(
        !rage_record_logic::should_retry_original_tick(4, 3, 4, 4),
        "adaptive unshifted result does not retry") && ok;
    ok = expect(
        !rage_record_logic::should_retry_original_tick(4, 2, 2, 4),
        "multi-tick native correction does not retry") && ok;
    ok = expect(
        !rage_record_logic::should_retry_original_tick(5, 4, 4, 4),
        "tick outside extended window does not retry") && ok;
    ok = expect(
        !rage_record_logic::should_retry_original_tick(0, -1, -1, 4),
        "negative adjusted tick does not retry") && ok;
    ok = expect(
        rage_record_logic::record_at(ring, 2) == &third,
        "wrapped record lookup with monotonic head") && ok;
    ok = expect(
        select_record(ring, 0x40600000u, 4) == &newest,
        "shot between newest records") && ok; // 3.5f
    ok = expect(
        select_record(ring, 0x40400000u, 4) == &second,
        "exact shot timestamp") && ok;
    ok = expect(
        select_record(ring, 0x40200000u, 4) == &second,
        "shot record pair selection") && ok; // 2.5f
    ok = expect(
        select_record(ring, 0x40200000u, 1) == nullptr,
        "pair search limit") && ok;

    second.valid = false;
    ok = expect(
        select_record(ring, 0x40200000u, 4) == nullptr,
        "invalid selected record") && ok;
    second.valid = true;

    third.simulation_bits = 0x40A00000u; // 5.0f, corrupt order
    ok = expect(
        select_record(ring, 0x40200000u, 4) == nullptr,
        "corrupt simulation order") && ok;
    third.simulation_bits = 0x40000000u;

    const auto invalid_ring = rage_record_logic::ring_view<test_record>{
        storage.data(),
        3,
        0,
        3
    };
    ok = expect(
        select_record(invalid_ring, 0x40400000u, 4) == nullptr,
        "non-power-of-two ring") && ok;
    const auto overfilled_ring = rage_record_logic::ring_view<test_record>{
        storage.data(),
        static_cast<std::uint32_t>(storage.size()),
        14,
        9
    };
    ok = expect(
        select_record(overfilled_ring, 0x40400000u, 4) == nullptr,
        "ring count above capacity") && ok;
    ok = expect(
        !rage_record_logic::positive_finite_float_bits(0x7F800000u),
        "infinite timestamp rejection") && ok;

    if (!ok)
        return 1;

    std::puts("PASS: rage record ring logic");
    return 0;
}
