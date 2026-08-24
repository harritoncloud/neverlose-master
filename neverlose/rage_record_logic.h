#pragma once

#include <cstdint>

namespace rage_record_logic
{
constexpr std::uint32_t kMaximumRingCapacity = 256;

inline std::int32_t choose_extended_tick_delta(
    std::int32_t requested_delta,
    std::int32_t native_delta,
    bool state_readable,
    bool state_classified,
    bool state_pending,
    std::int32_t maximum_delta)
{
    if (!state_readable ||
        maximum_delta < 0 ||
        requested_delta < 0 ||
        requested_delta > maximum_delta)
    {
        return native_delta;
    }

    const bool native_delta_valid =
        native_delta >= 0 && native_delta <= requested_delta;
    if (state_classified && !state_pending && native_delta_valid)
        return native_delta;

    // The native classifier is intentionally delayed until enough samples
    // exist. Keep the requested record usable while that state warms up.
    return requested_delta;
}

inline bool should_retry_original_tick(
    std::int32_t requested_delta,
    std::int32_t native_delta,
    std::int32_t returned_delta,
    std::int32_t maximum_delta)
{
    if (maximum_delta < 0 ||
        requested_delta < 0 ||
        requested_delta > maximum_delta)
    {
        return false;
    }

    // Retry only the exact one-tick correction made by the native classifier.
    return native_delta == returned_delta &&
        native_delta >= 0 &&
        native_delta == requested_delta - 1;
}

inline bool positive_finite_float_bits(std::uint32_t bits)
{
    return bits != 0 && bits < 0x7F800000u;
}

inline bool valid_ring_shape(
    std::uint32_t capacity,
    std::uint32_t head,
    std::uint32_t count)
{
    (void)head;
    return capacity != 0 &&
        capacity <= kMaximumRingCapacity &&
        (capacity & (capacity - 1)) == 0 &&
        count != 0 &&
        count <= capacity;
}

template <typename Record>
struct ring_view
{
    Record* const* records = nullptr;
    std::uint32_t capacity = 0;
    std::uint32_t head = 0;
    std::uint32_t count = 0;
};

template <typename Record>
Record* record_at(const ring_view<Record>& ring, std::uint32_t offset)
{
    if (!ring.records ||
        !valid_ring_shape(ring.capacity, ring.head, ring.count) ||
        offset >= ring.count)
    {
        return nullptr;
    }

    const std::uint32_t index =
        (ring.head + offset) & (ring.capacity - 1);
    return ring.records[index];
}

template <typename Record, typename ReadSimulationBits, typename AcceptRecord>
Record* find_shot_record(
    const ring_view<Record>& ring,
    std::uint32_t shot_time_bits,
    std::uint32_t maximum_pairs,
    ReadSimulationBits read_simulation_bits,
    AcceptRecord accept_record)
{
    if (!positive_finite_float_bits(shot_time_bits) || maximum_pairs == 0)
        return nullptr;

    Record* newer = record_at(ring, 0);
    if (!newer)
        return nullptr;

    std::uint32_t newer_bits = read_simulation_bits(newer);
    if (!positive_finite_float_bits(newer_bits))
        return nullptr;

    if (newer_bits == shot_time_bits)
        return accept_record(newer) ? newer : nullptr;

    std::uint32_t pair_count = ring.count - 1;
    if (pair_count > maximum_pairs)
        pair_count = maximum_pairs;

    for (std::uint32_t offset = 1; offset <= pair_count; ++offset)
    {
        Record* older = record_at(ring, offset);
        if (!older)
            return nullptr;

        const std::uint32_t older_bits = read_simulation_bits(older);
        if (!positive_finite_float_bits(older_bits) || newer_bits < older_bits)
            return nullptr;

        if (newer_bits >= shot_time_bits && shot_time_bits > older_bits)
            return accept_record(newer) ? newer : nullptr;

        newer = older;
        newer_bits = older_bits;
    }

    return nullptr;
}
}
