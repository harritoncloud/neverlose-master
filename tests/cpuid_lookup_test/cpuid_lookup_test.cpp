#include <cstdint>
#include <cstdio>

#include "../../neverlose/cpuid_emulator.h"

namespace
{
bool linear_lookup(DWORD address)
{
    for (const DWORD candidate : g_veh_cpuid_emus)
    {
        if (candidate == address)
            return true;
    }
    return false;
}
}

int main()
{
    for (size_t index = 1; index < g_sorted_veh_cpuid_emus.size(); ++index)
    {
        if (g_sorted_veh_cpuid_emus[index - 1] >
            g_sorted_veh_cpuid_emus[index])
        {
            std::puts("FAIL: sorted CPUID table order");
            return 1;
        }
    }

    for (const DWORD address : g_veh_cpuid_emus)
    {
        if (!is_veh_cpuid_address(address))
        {
            std::printf("FAIL: missing CPUID address 0x%08lX\n", address);
            return 2;
        }

        const DWORD neighbours[] = {address - 1u, address + 1u};
        for (const DWORD neighbour : neighbours)
        {
            if (is_veh_cpuid_address(neighbour) != linear_lookup(neighbour))
            {
                std::printf(
                    "FAIL: CPUID neighbour mismatch 0x%08lX\n",
                    neighbour);
                return 3;
            }
        }
    }

    constexpr DWORD invalid_samples[] = {
        0u,
        1u,
        0x412A0000u,
        0xFFFFFFFFu
    };
    for (const DWORD address : invalid_samples)
    {
        if (is_veh_cpuid_address(address) != linear_lookup(address))
        {
            std::puts("FAIL: invalid CPUID sample mismatch");
            return 4;
        }
    }

    std::printf(
        "PASS: binary CPUID lookup matches %zu source addresses\n",
        g_veh_cpuid_emus.size());
    return 0;
}
