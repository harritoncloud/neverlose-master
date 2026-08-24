#define NOMINMAX
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../../neverlose/Hide.h"
#include "../../neverlose/fix_anim_layers_preserve.h"
#include "../../neverlose/fix_lerp_disable.h"
#include "../../neverlose/fix_menu_extra.h"
#include "../../neverlose/fix_persist.h"
#include "../../neverlose/fix_rage_records.h"
#include "../../neverlose/fix_records_size.h"

static constexpr uintptr_t TEST_IMAGE_BASE = 0x412A0000;
static constexpr uintptr_t ANIM_DISPATCH_SITE = 0x41B73AA6;
static constexpr uintptr_t HIDE_PROBE_SITE = 0x4151B37E;
static constexpr uintptr_t BRANDING_PROBE_SITE = 0x4151B301;

using test_animation_update_fn = void(__thiscall*)(void*);
extern "C" void __fastcall anim_layers_sanitize_update(
    void* entity,
    test_animation_update_fn update);

static bool g_write_invalid_animation_layers = false;

struct PatchProbe
{
    uintptr_t address;
    size_t size;
    std::array<uint8_t, 12> original;
    std::array<uint8_t, 12> desired;
};

static bool read_image(const wchar_t* path, void*& image, DWORD& image_size)
{
    HANDLE file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    image_size = GetFileSize(file, nullptr);
    if (image_size == INVALID_FILE_SIZE || !image_size)
    {
        CloseHandle(file);
        return false;
    }

    image = VirtualAlloc(
        reinterpret_cast<void*>(TEST_IMAGE_BASE),
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (image != reinterpret_cast<void*>(TEST_IMAGE_BASE))
    {
        if (image)
            VirtualFree(image, 0, MEM_RELEASE);
        image = nullptr;
        CloseHandle(file);
        return false;
    }

    DWORD bytes_read = 0;
    const BOOL read = ReadFile(
        file,
        image,
        image_size,
        &bytes_read,
        nullptr);
    CloseHandle(file);
    if (!read || bytes_read != image_size)
    {
        VirtualFree(image, 0, MEM_RELEASE);
        image = nullptr;
        return false;
    }

    return true;
}

static void snapshot_bytes(
    PatchProbe& probe,
    std::array<uint8_t, 12>& destination)
{
    memcpy(
        destination.data(),
        reinterpret_cast<const void*>(probe.address),
        probe.size);
}

static bool write_bytes(
    uintptr_t address,
    const uint8_t* source,
    size_t size)
{
    DWORD old_protection = 0;
    if (!VirtualProtect(
            reinterpret_cast<void*>(address),
            size,
            PAGE_EXECUTE_READWRITE,
            &old_protection))
    {
        return false;
    }

    memcpy(reinterpret_cast<void*>(address), source, size);
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
    return flushed && restored;
}

static bool matches(const PatchProbe& probe)
{
    return memcmp(
        reinterpret_cast<const void*>(probe.address),
        probe.desired.data(),
        probe.size) == 0;
}

static bool wait_for_match(const PatchProbe& probe, DWORD timeout_ms)
{
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    while (GetTickCount64() < deadline)
    {
        if (matches(probe))
            return true;
        Sleep(10);
    }
    return matches(probe);
}

static bool patch_should_change(uintptr_t address)
{
    switch (address)
    {
    case BT_RATIO_LOAD_1:
    case BT_RATIO_LOAD_2:
    case RECWIN_COMPARE_1:
    case RECWIN_COMPARE_2:
    case ANIM_DISPATCH_SITE:
    case HIDE_PROBE_SITE:
    case BRANDING_PROBE_SITE:
    case 0x413F9607:
    case 0x414002A4:
    case 0x41478602:
    case 0x4148186F:
    case 0x4148475E:
    case 0x4149BBE2:
    case 0x4149FA45:
    case 0x414A8F55:
    case 0x414BA7F9:
    case 0x414002B8:
    case 0x4149FA50:
    case 0x414A8F69:
        return true;
    default:
        return false;
    }
}

static bool is_tick_delta_site(uintptr_t address)
{
    switch (address)
    {
    case 0x413F9607:
    case 0x414002A4:
    case 0x41478602:
    case 0x4148186F:
    case 0x4148475E:
    case 0x4149BBE2:
    case 0x4149FA45:
    case 0x414A8F55:
    case 0x414BA7F9:
        return true;
    default:
        return false;
    }
}

static bool is_lookup_retry_site(uintptr_t address)
{
    switch (address)
    {
    case 0x414002B8:
    case 0x4149FA50:
    case 0x414A8F69:
        return true;
    default:
        return false;
    }
}

static uintptr_t relative_call_target(const PatchProbe& probe)
{
    if (probe.size != 5 || probe.desired[0] != 0xE8)
        return 0;

    int32_t displacement = 0;
    memcpy(&displacement, probe.desired.data() + 1, sizeof(displacement));
    return probe.address + 5 + displacement;
}

static uint64_t process_cpu_time_100ns()
{
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    if (!GetProcessTimes(
            GetCurrentProcess(),
            &creation,
            &exit,
            &kernel,
            &user))
    {
        return 0;
    }

    ULARGE_INTEGER kernel_value{};
    kernel_value.LowPart = kernel.dwLowDateTime;
    kernel_value.HighPart = kernel.dwHighDateTime;
    ULARGE_INTEGER user_value{};
    user_value.LowPart = user.dwLowDateTime;
    user_value.HighPart = user.dwHighDateTime;
    return kernel_value.QuadPart + user_value.QuadPart;
}

static uint32_t float_bits(float value)
{
    uint32_t bits = 0;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

static void write_layer_bits(uint8_t* layers, size_t offset, uint32_t bits)
{
    *reinterpret_cast<uint32_t*>(layers + offset) = bits;
}

static uint32_t read_layer_bits(const uint8_t* layers, size_t offset)
{
    return *reinterpret_cast<const uint32_t*>(layers + offset);
}

static void __fastcall synthetic_animation_update(void* entity)
{
    auto* entity_bytes = static_cast<uint8_t*>(entity);
    auto* layers = *reinterpret_cast<uint8_t**>(entity_bytes + 0x2990);
    if (g_write_invalid_animation_layers)
    {
        write_layer_bits(layers, 0x250, 0x7FC00000u);
        write_layer_bits(layers, 0x25C, 0x7F800000u);
        write_layer_bits(layers, 0x288, 0xFFC00000u);
        write_layer_bits(layers, 0x294, 0xFF800000u);
        return;
    }

    write_layer_bits(layers, 0x250, float_bits(0.75f));
    write_layer_bits(layers, 0x25C, float_bits(0.80f));
    write_layer_bits(layers, 0x288, float_bits(0.85f));
    write_layer_bits(layers, 0x294, float_bits(0.90f));
}

static bool test_animation_layer_sanitizer()
{
    alignas(void*) std::array<uint8_t, 0x2A00> entity{};
    alignas(void*) std::array<uint8_t, 0x2A0> layers{};
    *reinterpret_cast<uint8_t**>(entity.data() + 0x2990) = layers.data();
    *reinterpret_cast<uint32_t*>(entity.data() + 0x299C) = 12;
    *reinterpret_cast<void**>(layers.data() + 0x260) = entity.data();
    *reinterpret_cast<void**>(layers.data() + 0x298) = entity.data();

    write_layer_bits(layers.data(), 0x250, float_bits(0.10f));
    write_layer_bits(layers.data(), 0x25C, float_bits(0.20f));
    write_layer_bits(layers.data(), 0x288, float_bits(0.30f));
    write_layer_bits(layers.data(), 0x294, float_bits(0.40f));

    g_write_invalid_animation_layers = false;
    anim_layers_sanitize_update(
        entity.data(),
        reinterpret_cast<test_animation_update_fn>(
            &synthetic_animation_update));
    if (read_layer_bits(layers.data(), 0x250) != float_bits(0.75f) ||
        read_layer_bits(layers.data(), 0x25C) != float_bits(0.80f) ||
        read_layer_bits(layers.data(), 0x288) != float_bits(0.85f) ||
        read_layer_bits(layers.data(), 0x294) != float_bits(0.90f))
    {
        return false;
    }

    const std::array<uint32_t, 4> stable = {
        float_bits(0.15f),
        float_bits(0.25f),
        float_bits(0.35f),
        float_bits(0.45f)
    };
    write_layer_bits(layers.data(), 0x250, stable[0]);
    write_layer_bits(layers.data(), 0x25C, stable[1]);
    write_layer_bits(layers.data(), 0x288, stable[2]);
    write_layer_bits(layers.data(), 0x294, stable[3]);

    g_write_invalid_animation_layers = true;
    anim_layers_sanitize_update(
        entity.data(),
        reinterpret_cast<test_animation_update_fn>(
            &synthetic_animation_update));
    return read_layer_bits(layers.data(), 0x250) == stable[0] &&
        read_layer_bits(layers.data(), 0x25C) == stable[1] &&
        read_layer_bits(layers.data(), 0x288) == stable[2] &&
        read_layer_bits(layers.data(), 0x294) == stable[3];
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2)
    {
        std::puts("FAIL: expected nl.bin path");
        return 1;
    }

    if (!test_animation_layer_sanitizer())
    {
        std::puts("FAIL: animation layer sanitizer behavior");
        return 2;
    }

    void* image = nullptr;
    DWORD image_size = 0;
    if (!read_image(argv[1], image, image_size))
    {
        std::puts("FAIL: map nl.bin");
        return 2;
    }

    std::array<PatchProbe, 44> probes = {{
        {BT_RATIO_LOAD_1, BT_RATIO_LOAD_SIZE, {}, {}},
        {BT_RATIO_LOAD_2, BT_RATIO_LOAD_SIZE, {}, {}},
        {LERP1B_ADDR, LERP_NOP_LEN, {}, {}},
        {LERP1A_ADDR, LERP_NOP_LEN, {}, {}},
        {LERP2B_ADDR, LERP_NOP_LEN, {}, {}},
        {LERP2A_ADDR, LERP_NOP_LEN, {}, {}},
        {RECWIN_COMPARE_1, 9, {}, {}},
        {RECWIN_COMPARE_2, 9, {}, {}},
        {ANIM_DISPATCH_SITE, 6, {}, {}},
        {HIDE_PROBE_SITE, 5, {}, {}},
        {BRANDING_PROBE_SITE, 4, {}, {}},
        {0x413F9607, 5, {}, {}},
        {0x414002A4, 5, {}, {}},
        {0x41478602, 5, {}, {}},
        {0x4148186F, 5, {}, {}},
        {0x4148475E, 5, {}, {}},
        {0x4149BBE2, 5, {}, {}},
        {0x4149FA45, 5, {}, {}},
        {0x414A8F55, 5, {}, {}},
        {0x414BA7F9, 5, {}, {}},
        {0x41477BDD, 5, {}, {}},
        {0x414964C1, 5, {}, {}},
        {0x4148F5B4, 5, {}, {}},
        {0x4149C3AD, 5, {}, {}},
        {0x414ABDF1, 5, {}, {}},
        {0x4148F4B9, 5, {}, {}},
        {0x4148F533, 2, {}, {}},
        {0x4148F1A7, 5, {}, {}},
        {0x4148F4BE, 7, {}, {}},
        {0x4148F2A8, 5, {}, {}},
        {0x4148EE5C, 6, {}, {}},
        {0x4148C9CE, 6, {}, {}},
        {0x4148EF24, 6, {}, {}},
        {0x4148124E, 5, {}, {}},
        {0x414840AF, 5, {}, {}},
        {0x4148F793, 5, {}, {}},
        {0x4148F786, 5, {}, {}},
        {0x4148FE15, 5, {}, {}},
        {0x4149010C, 5, {}, {}},
        {0x4148F1DA, 11, {}, {}},
        {0x4148F356, 12, {}, {}},
        {0x414002B8, 5, {}, {}},
        {0x4149FA50, 5, {}, {}},
        {0x414A8F69, 5, {}, {}}
    }};
    for (PatchProbe& probe : probes)
        snapshot_bytes(probe, probe.original);

    PatchProbe& ratio_conflict_probe = probes[0];
    const uint8_t ratio_conflict_byte =
        static_cast<uint8_t>(ratio_conflict_probe.original[0] ^ 0xFF);
    if (!write_bytes(
            ratio_conflict_probe.address,
            &ratio_conflict_byte,
            1) ||
        apply_bt_ratio_unlock())
    {
        std::puts("FAIL: BT ratio conflict was not rejected");
        VirtualFree(image, 0, MEM_RELEASE);
        return 3;
    }
    for (size_t index = 1; index < 6; ++index)
    {
        if (memcmp(
                reinterpret_cast<const void*>(probes[index].address),
                probes[index].original.data(),
                probes[index].size) != 0)
        {
            std::puts("FAIL: BT ratio conflict caused a partial write");
            VirtualFree(image, 0, MEM_RELEASE);
            return 4;
        }
    }
    if (!write_bytes(
            ratio_conflict_probe.address,
            ratio_conflict_probe.original.data(),
            ratio_conflict_probe.size))
    {
        std::puts("FAIL: BT ratio conflict restore");
        VirtualFree(image, 0, MEM_RELEASE);
        return 5;
    }

    PatchProbe& history_conflict_probe = probes[6];
    const uint8_t history_conflict_byte =
        static_cast<uint8_t>(history_conflict_probe.original[0] ^ 0xFF);
    if (!write_bytes(
            history_conflict_probe.address,
            &history_conflict_byte,
            1) ||
        apply_records_size_fix())
    {
        std::puts("FAIL: BT history conflict was not rejected");
        VirtualFree(image, 0, MEM_RELEASE);
        return 6;
    }
    if (memcmp(
            reinterpret_cast<const void*>(probes[7].address),
            probes[7].original.data(),
            probes[7].size) != 0)
    {
        std::puts("FAIL: BT history conflict caused a partial write");
        VirtualFree(image, 0, MEM_RELEASE);
        return 7;
    }
    if (!write_bytes(
            history_conflict_probe.address,
            history_conflict_probe.original.data(),
            history_conflict_probe.size))
    {
        std::puts("FAIL: BT history conflict restore");
        VirtualFree(image, 0, MEM_RELEASE);
        return 8;
    }

    PatchProbe& conflict_probe = probes[11];
    const uint8_t conflict_byte =
        static_cast<uint8_t>(conflict_probe.original[0] ^ 0xFF);
    if (!write_bytes(conflict_probe.address, &conflict_byte, 1) ||
        apply_rage_record_patches())
    {
        std::puts("FAIL: rage conflict was not rejected");
        VirtualFree(image, 0, MEM_RELEASE);
        return 9;
    }
    for (size_t index = 12; index < probes.size(); ++index)
    {
        if (memcmp(
                reinterpret_cast<const void*>(probes[index].address),
                probes[index].original.data(),
                probes[index].size) != 0)
        {
            std::puts("FAIL: rage conflict caused a partial write");
            VirtualFree(image, 0, MEM_RELEASE);
            return 10;
        }
    }
    if (!write_bytes(
            conflict_probe.address,
            conflict_probe.original.data(),
            conflict_probe.size))
    {
        std::puts("FAIL: rage conflict restore");
        VirtualFree(image, 0, MEM_RELEASE);
        return 11;
    }

    if (!apply_records_size_fix() || !apply_bt_ratio_unlock())
    {
        std::puts("FAIL: safe BT unlocks were not installed");
        VirtualFree(image, 0, MEM_RELEASE);
        return 12;
    }
    const uintptr_t ratio_pointer_1 =
        *reinterpret_cast<const uint32_t*>(BT_RATIO_OPERAND_1);
    const uintptr_t ratio_pointer_2 =
        *reinterpret_cast<const uint32_t*>(BT_RATIO_OPERAND_2);
    if (ratio_pointer_1 != ratio_pointer_2 ||
        *reinterpret_cast<const uint32_t*>(ratio_pointer_1) != 0x3F800000u)
    {
        std::puts("FAIL: BT ratio unlock is not isolated at 1.0f");
        VirtualFree(image, 0, MEM_RELEASE);
        return 12;
    }
    apply_anim_layers_preserve();
    apply_menu_extra();
    apply_Hide();
    if (!apply_rage_record_patches())
    {
        std::puts("FAIL: rage patches were not installed");
        VirtualFree(image, 0, MEM_RELEASE);
        return 13;
    }

    for (size_t index = 0; index < probes.size(); ++index)
    {
        PatchProbe& probe = probes[index];
        snapshot_bytes(probe, probe.desired);
        const bool changed = memcmp(
            probe.original.data(),
            probe.desired.data(),
            probe.size) != 0;
        if (changed != patch_should_change(probe.address))
        {
            std::puts("FAIL: rage safe-profile patch set mismatch");
            VirtualFree(image, 0, MEM_RELEASE);
            return 7;
        }
    }

    uintptr_t shared_tick_delta_target = 0;
    size_t tick_delta_site_count = 0;
    for (const PatchProbe& probe : probes)
    {
        if (!is_tick_delta_site(probe.address))
            continue;

        const uintptr_t target = relative_call_target(probe);
        if (!target || target == 0x413341E0 ||
            (shared_tick_delta_target != 0 &&
                target != shared_tick_delta_target))
        {
            std::puts("FAIL: tick-delta paths do not share one adaptive wrapper");
            VirtualFree(image, 0, MEM_RELEASE);
            return 7;
        }

        shared_tick_delta_target = target;
        ++tick_delta_site_count;
    }
    if (tick_delta_site_count != 9)
    {
        std::puts("FAIL: not all tick-delta paths were patched");
        VirtualFree(image, 0, MEM_RELEASE);
        return 7;
    }

    uintptr_t shared_lookup_retry_target = 0;
    size_t lookup_retry_site_count = 0;
    for (const PatchProbe& probe : probes)
    {
        if (!is_lookup_retry_site(probe.address))
            continue;

        const uintptr_t target = relative_call_target(probe);
        if (!target || target == 0x4135F0E0 ||
            (shared_lookup_retry_target != 0 &&
                target != shared_lookup_retry_target))
        {
            std::puts("FAIL: strict lookup paths do not share null-only retry");
            VirtualFree(image, 0, MEM_RELEASE);
            return 7;
        }

        shared_lookup_retry_target = target;
        ++lookup_retry_site_count;
    }
    if (lookup_retry_site_count != 3)
    {
        std::puts("FAIL: strict lookup retry coverage mismatch");
        VirtualFree(image, 0, MEM_RELEASE);
        return 7;
    }

    start_persist_watchdog();
    Sleep(25);

    wchar_t benchmark_text[32]{};
    const DWORD benchmark_length = GetEnvironmentVariableW(
        L"PERSIST_IDLE_BENCHMARK_MS",
        benchmark_text,
        static_cast<DWORD>(std::size(benchmark_text)));
    if (benchmark_length != 0 &&
        benchmark_length < std::size(benchmark_text))
    {
        const unsigned long benchmark_ms = std::wcstoul(
            benchmark_text,
            nullptr,
            10);
        if (benchmark_ms != 0)
        {
            const uint64_t before = process_cpu_time_100ns();
            Sleep(benchmark_ms);
            const uint64_t after = process_cpu_time_100ns();
            std::printf(
                "BENCH: idle watchdog cpu=%llu us over %lu ms\n",
                static_cast<unsigned long long>((after - before) / 10),
                benchmark_ms);
        }
    }

    for (const PatchProbe& probe : probes)
    {
        if (!write_bytes(
                probe.address,
                probe.original.data(),
                probe.size))
        {
            std::puts("FAIL: restore simulation");
            request_persist_watchdog_stop();
            return 8;
        }
    }

    const ULONGLONG deadline = GetTickCount64() + 3000;
    bool recovered = false;
    while (GetTickCount64() < deadline)
    {
        recovered = true;
        for (const PatchProbe& probe : probes)
        {
            if (!matches(probe))
            {
                recovered = false;
                break;
            }
        }

        if (recovered)
            break;
        Sleep(10);
    }

    if (!recovered)
    {
        request_persist_watchdog_stop();
        std::puts("FAIL: persist callback recovery");
        return 9;
    }

    PatchProbe& contention_probe = probes[11];
    for (int cycle = 0; cycle < 2; ++cycle)
    {
        if (!write_bytes(
                contention_probe.address,
                contention_probe.original.data(),
                contention_probe.size) ||
            !wait_for_match(contention_probe, 1000))
        {
            request_persist_watchdog_stop();
            std::puts("FAIL: watchdog contention setup");
            return 10;
        }
    }

    if (!write_bytes(
            contention_probe.address,
            contention_probe.original.data(),
            contention_probe.size))
    {
        request_persist_watchdog_stop();
        std::puts("FAIL: watchdog quarantine write");
        return 11;
    }
    Sleep(750);
    if (matches(contention_probe))
    {
        request_persist_watchdog_stop();
        std::puts("FAIL: watchdog contention circuit breaker");
        return 12;
    }

    request_persist_watchdog_stop();
    Sleep(100);

    std::puts("PASS: real persist callback recovery");
    return 0;
}
