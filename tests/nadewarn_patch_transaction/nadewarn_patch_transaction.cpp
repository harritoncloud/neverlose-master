#include <cstdio>
#include <cstring>
#include <intrin.h>

#include "../../neverlose/fix_persist.cpp"
#include "../../neverlose/nadewarn.cpp"

static volatile LONG g_worker_running = 0;
static volatile LONG g_worker_ready = 0;
static volatile LONG g_worker_heartbeat = 0;
static volatile LONG g_generic_writer_calls = 0;
static volatile LONG g_fault_writer_calls = 0;
static uint8_t* g_generic_patch_target = nullptr;

#pragma optimize("", off)
__declspec(noinline) static DWORD WINAPI patch_test_worker(PVOID)
{
    InterlockedExchange(&g_worker_ready, 1);
    while (InterlockedCompareExchange(&g_worker_running, 1, 1) == 1)
    {
        InterlockedIncrement(&g_worker_heartbeat);
        _ReadWriteBarrier();
        YieldProcessor();
    }
    return 0;
}
#pragma optimize("", on)

static std::array<
    std::array<uint8_t, NW_MAX_PATCH_SIZE>,
    NW_PATCH_COUNT> g_test_originals{};
static std::array<
    std::array<uint8_t, NW_MAX_PATCH_SIZE>,
    NW_PATCH_COUNT> g_test_replacements{};
static std::array<
    std::array<uint8_t, NW_MAX_PATCH_SIZE>,
    NW_PATCH_COUNT> g_test_alternates{};

static constexpr size_t TEST_PATCH_SIZE = 5;
static constexpr size_t TEST_PATCH_STRIDE = 16;
static constexpr uint8_t GENERIC_ORIGINAL[] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60
};
static constexpr uint8_t GENERIC_REPLACEMENT[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

static bool write_test_memory(
    void* address,
    const void* data,
    size_t size)
{
    DWORD old_protection = 0;
    if (!VirtualProtect(
            address,
            size,
            PAGE_EXECUTE_READWRITE,
            &old_protection))
    {
        return false;
    }

    memcpy(address, data, size);
    const BOOL flushed = FlushInstructionCache(
        GetCurrentProcess(),
        address,
        size);

    DWORD ignored_protection = 0;
    const BOOL restored = VirtualProtect(
        address,
        size,
        old_protection,
        &ignored_protection);
    return flushed && restored;
}

static bool has_execute_read_protection(const void* address)
{
    MEMORY_BASIC_INFORMATION information{};
    if (!VirtualQuery(address, &information, sizeof(information)))
        return false;

    return (information.Protect & 0xFF) == PAGE_EXECUTE_READ;
}

static void generic_patch_writer()
{
    InterlockedIncrement(&g_generic_writer_calls);
    write_test_memory(
        g_generic_patch_target,
        GENERIC_REPLACEMENT,
        sizeof(GENERIC_REPLACEMENT));
}

static void faulting_patch_writer()
{
    InterlockedIncrement(&g_fault_writer_calls);
    RaiseException(0xE0424242, 0, 0, nullptr);
}

static void configure_test_patches(uint8_t* memory)
{
    for (size_t i = 0; i < NW_PATCH_COUNT; ++i)
    {
        for (size_t byte = 0; byte < TEST_PATCH_SIZE; ++byte)
        {
            g_test_originals[i][byte] =
                static_cast<uint8_t>(0x10 + i + byte);
            g_test_replacements[i][byte] =
                static_cast<uint8_t>(0xA0 + i + byte);
            g_test_alternates[i][byte] =
                static_cast<uint8_t>(0x60 + i + byte);
        }

        uint8_t* target = memory + i * TEST_PATCH_STRIDE;
        memcpy(target, g_test_originals[i].data(), TEST_PATCH_SIZE);
        g_nw_patches[i] = {
            reinterpret_cast<uintptr_t>(target),
            g_test_originals[i].data(),
            g_test_replacements[i].data(),
            i == 2 ? g_test_alternates[i].data() : nullptr,
            TEST_PATCH_SIZE,
            reinterpret_cast<uintptr_t>(target),
            TEST_PATCH_SIZE
        };
    }

    g_nw_patch_count = NW_PATCH_COUNT;
}

static bool patch_matches(
    const uint8_t* memory,
    size_t index,
    const std::array<uint8_t, NW_MAX_PATCH_SIZE>& expected)
{
    return memcmp(
        memory + index * TEST_PATCH_STRIDE,
        expected.data(),
        TEST_PATCH_SIZE) == 0;
}

static bool all_replacements_match(const uint8_t* memory)
{
    for (size_t i = 0; i < NW_PATCH_COUNT; ++i)
    {
        if (!patch_matches(memory, i, g_test_replacements[i]))
            return false;
    }
    return true;
}

static void stop_worker(HANDLE worker)
{
    if (!worker)
        return;

    InterlockedExchange(&g_worker_running, 0);
    WaitForSingleObject(worker, 2000);
    CloseHandle(worker);
}

int main()
{
    auto* memory = static_cast<uint8_t*>(VirtualAlloc(
        nullptr,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));
    if (!memory)
    {
        std::puts("FAIL: VirtualAlloc");
        return 1;
    }

    configure_test_patches(memory);

    DWORD old_protection = 0;
    if (!VirtualProtect(
            memory,
            4096,
            PAGE_EXECUTE_READ,
            &old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(), memory, 4096))
    {
        std::puts("FAIL: initial page protection");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 2;
    }

    if (!nw_apply_patch_set(false) ||
        !all_replacements_match(memory) ||
        !has_execute_read_protection(memory))
    {
        std::puts("FAIL: initial transaction");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 3;
    }

    std::array<bool, NW_PATCH_COUNT> attempted{};
    std::array<
        std::array<uint8_t, NW_MAX_PATCH_SIZE>,
        NW_PATCH_COUNT> previous{};
    for (size_t i = 0; i < 2; ++i)
    {
        attempted[i] = true;
        memcpy(
            previous[i].data(),
            g_test_originals[i].data(),
            TEST_PATCH_SIZE);
    }
    if (!nw_rollback(attempted, previous) ||
        !patch_matches(memory, 0, g_test_originals[0]) ||
        !patch_matches(memory, 1, g_test_originals[1]) ||
        !has_execute_read_protection(memory))
    {
        std::puts("FAIL: rollback");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 4;
    }

    if (!nw_apply_patch_set(false) ||
        !all_replacements_match(memory))
    {
        std::puts("FAIL: post-rollback transaction");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 5;
    }

    if (!write_test_memory(
            memory + 2 * TEST_PATCH_STRIDE,
            g_test_alternates[2].data(),
            TEST_PATCH_SIZE) ||
        !nw_apply_patch_set(false) ||
        !patch_matches(memory, 2, g_test_replacements[2]))
    {
        std::puts("FAIL: alternate-original recovery");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 6;
    }

    std::array<uint8_t, TEST_PATCH_SIZE> unknown{};
    unknown.fill(0x7F);
    if (!write_test_memory(
            memory,
            g_test_originals[0].data(),
            TEST_PATCH_SIZE) ||
        !write_test_memory(
            memory + TEST_PATCH_STRIDE,
            unknown.data(),
            unknown.size()))
    {
        std::puts("FAIL: unknown-byte setup");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 7;
    }

    if (nw_apply_patch_set(false) ||
        !patch_matches(memory, 0, g_test_originals[0]) ||
        memory[TEST_PATCH_STRIDE] != 0x7F ||
        !has_execute_read_protection(memory))
    {
        std::puts("FAIL: unknown-byte rejection");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 8;
    }

    if (!write_test_memory(
            memory + TEST_PATCH_STRIDE,
            g_test_replacements[1].data(),
            TEST_PATCH_SIZE))
    {
        std::puts("FAIL: worker test setup");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 9;
    }

    InterlockedExchange(&g_worker_running, 1);
    InterlockedExchange(&g_worker_ready, 0);
    InterlockedExchange(&g_worker_heartbeat, 0);
    HANDLE worker = CreateThread(
        nullptr,
        0,
        patch_test_worker,
        nullptr,
        0,
        nullptr);
    if (!worker)
    {
        std::puts("FAIL: CreateThread");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 10;
    }

    const ULONGLONG ready_deadline = GetTickCount64() + 2000;
    while (InterlockedCompareExchange(&g_worker_ready, 1, 1) != 1 &&
           GetTickCount64() < ready_deadline)
    {
        Sleep(1);
    }
    if (InterlockedCompareExchange(&g_worker_ready, 1, 1) != 1)
    {
        std::puts("FAIL: worker startup");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 11;
    }

    if (!nw_apply_patch_set(true) ||
        !patch_matches(memory, 0, g_test_replacements[0]))
    {
        std::puts("FAIL: suspended-thread recovery");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 12;
    }

    if (!write_test_memory(
            memory,
            g_test_originals[0].data(),
            TEST_PATCH_SIZE))
    {
        std::puts("FAIL: EIP test setup");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 13;
    }

    MEMORY_BASIC_INFORMATION worker_region{};
    if (!VirtualQuery(
            reinterpret_cast<const void*>(&patch_test_worker),
            &worker_region,
            sizeof(worker_region)))
    {
        std::puts("FAIL: worker VirtualQuery");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 14;
    }

    g_nw_patches[0].instruction_address =
        reinterpret_cast<uintptr_t>(worker_region.BaseAddress);
    g_nw_patches[0].instruction_size = worker_region.RegionSize;

    if (nw_apply_patch_set(true) ||
        !patch_matches(memory, 0, g_test_originals[0]))
    {
        std::puts("FAIL: EIP hazard rejection");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 15;
    }

    g_nw_patches[0].instruction_address =
        reinterpret_cast<uintptr_t>(memory);
    g_nw_patches[0].instruction_size = TEST_PATCH_SIZE;
    if (!nw_apply_patch_set(true) ||
        !patch_matches(memory, 0, g_test_replacements[0]))
    {
        std::puts("FAIL: post-hazard recovery");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 16;
    }

    g_generic_patch_target =
        memory + NW_PATCH_COUNT * TEST_PATCH_STRIDE + 64;
    if (!write_test_memory(
            g_generic_patch_target,
            GENERIC_ORIGINAL,
            sizeof(GENERIC_ORIGINAL)))
    {
        std::puts("FAIL: generic transaction setup");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 17;
    }

    patch_code_range generic_range = {
        reinterpret_cast<uintptr_t>(g_generic_patch_target),
        sizeof(GENERIC_ORIGINAL)
    };
    InterlockedExchange(&g_generic_writer_calls, 0);
    acquire_patch_write_lock();
    const bool generic_applied =
        run_persist_patch_transaction_locked(
            &generic_range,
            1,
            generic_patch_writer);
    release_patch_write_lock();
    if (!generic_applied ||
        InterlockedCompareExchange(
            &g_generic_writer_calls, 0, 0) != 1 ||
        memcmp(
            g_generic_patch_target,
            GENERIC_REPLACEMENT,
            sizeof(GENERIC_REPLACEMENT)) != 0 ||
        !has_execute_read_protection(memory))
    {
        std::puts("FAIL: generic transaction");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 18;
    }

    if (!write_test_memory(
            g_generic_patch_target,
            GENERIC_ORIGINAL,
            sizeof(GENERIC_ORIGINAL)))
    {
        std::puts("FAIL: generic EIP setup");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 19;
    }

    patch_code_range worker_hazard = {
        reinterpret_cast<uintptr_t>(worker_region.BaseAddress),
        worker_region.RegionSize
    };
    InterlockedExchange(&g_generic_writer_calls, 0);
    acquire_patch_write_lock();
    const bool generic_hazard_applied =
        run_persist_patch_transaction_locked(
            &worker_hazard,
            1,
            generic_patch_writer);
    release_patch_write_lock();
    if (generic_hazard_applied ||
        InterlockedCompareExchange(
            &g_generic_writer_calls, 0, 0) != 0 ||
        memcmp(
            g_generic_patch_target,
            GENERIC_ORIGINAL,
            sizeof(GENERIC_ORIGINAL)) != 0)
    {
        std::puts("FAIL: generic EIP hazard rejection");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 20;
    }

    const LONG heartbeat_before = InterlockedCompareExchange(
        &g_worker_heartbeat,
        0,
        0);
    InterlockedExchange(&g_fault_writer_calls, 0);
    acquire_patch_write_lock();
    const bool fault_writer_applied =
        run_persist_patch_transaction_locked(
            &generic_range,
            1,
            faulting_patch_writer);
    release_patch_write_lock();
    Sleep(10);
    const LONG heartbeat_after = InterlockedCompareExchange(
        &g_worker_heartbeat,
        0,
        0);
    if (fault_writer_applied ||
        InterlockedCompareExchange(
            &g_fault_writer_calls, 0, 0) != 1 ||
        heartbeat_after == heartbeat_before)
    {
        std::puts("FAIL: SEH thaw guarantee");
        stop_worker(worker);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 21;
    }

    stop_worker(worker);

    auto* separate_memory = static_cast<uint8_t*>(VirtualAlloc(
        nullptr,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));
    if (!separate_memory)
    {
        std::puts("FAIL: fallback-region allocation");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 22;
    }

    constexpr size_t fallback_index = NW_PATCH_COUNT - 1;
    memcpy(
        separate_memory,
        g_test_originals[fallback_index].data(),
        TEST_PATCH_SIZE);
    DWORD separate_old_protection = 0;
    if (!VirtualProtect(
            separate_memory,
            4096,
            PAGE_EXECUTE_READ,
            &separate_old_protection))
    {
        std::puts("FAIL: fallback-region protection");
        VirtualFree(separate_memory, 0, MEM_RELEASE);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 23;
    }

    const NwPatch saved_patch = g_nw_patches[fallback_index];
    g_nw_patches[fallback_index].address =
        reinterpret_cast<uintptr_t>(separate_memory);
    g_nw_patches[fallback_index].instruction_address =
        reinterpret_cast<uintptr_t>(separate_memory);
    g_nw_patches[fallback_index].instruction_size = TEST_PATCH_SIZE;

    const bool fallback_applied = nw_apply_patch_set(false);
    const bool fallback_matches = memcmp(
        separate_memory,
        g_test_replacements[fallback_index].data(),
        TEST_PATCH_SIZE) == 0;
    g_nw_patches[fallback_index] = saved_patch;
    VirtualFree(separate_memory, 0, MEM_RELEASE);
    if (!fallback_applied || !fallback_matches)
    {
        std::puts("FAIL: discontiguous patch fallback");
        VirtualFree(memory, 0, MEM_RELEASE);
        return 24;
    }

    void* inaccessible = VirtualAlloc(
        nullptr,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_NOACCESS);
    if (!inaccessible ||
        nw_bytes_equal(
            reinterpret_cast<uintptr_t>(inaccessible),
            g_test_replacements[0].data(),
            TEST_PATCH_SIZE))
    {
        std::puts("FAIL: inaccessible comparison fail-safe");
        if (inaccessible)
            VirtualFree(inaccessible, 0, MEM_RELEASE);
        VirtualFree(memory, 0, MEM_RELEASE);
        return 25;
    }
    VirtualFree(inaccessible, 0, MEM_RELEASE);

    VirtualFree(memory, 0, MEM_RELEASE);
    std::puts("PASS: nadewarn and common patch transactions");
    return 0;
}
