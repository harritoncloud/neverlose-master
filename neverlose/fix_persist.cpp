// ============================================================
//  fix_persist.cpp
//
//  Single unified persist watchdog thread.
//  Runs all registered check-before-write callbacks every 250ms.
//  Each callback is wrapped in its own SEH so one crash doesn't
//  take down the others.
// ============================================================

#include "neverlose.h"
#include <TlHelp32.h>
#include <cstdint>

#include "fix_persist.h"

// ---------------------------------------------------------------------------
// Callback registry
// ---------------------------------------------------------------------------
static persist_fn_t g_callbacks[MAX_PERSIST_CALLBACKS] = {};
static int          g_callback_count                   = 0;
static volatile LONG g_watchdog_started                = 0;
static HANDLE       g_watchdog_thread                  = nullptr;
static HANDLE       g_watchdog_stop_event              = nullptr;
static SRWLOCK      g_patch_write_lock                 = SRWLOCK_INIT;
static volatile LONG g_watchdog_callback_active        = 0;
static volatile LONG g_watchdog_repair_attempted       = 0;
static volatile LONG g_runtime_repairs_quarantined     = 0;
static ULONGLONG    g_repair_window_started            = 0;
static unsigned     g_repair_cycle_count               = 0;

static constexpr DWORD WATCHDOG_INTERVAL_MS = 250;
static constexpr ULONGLONG REPAIR_WINDOW_MS = 2000;
static constexpr unsigned MAX_REPAIR_CYCLES_PER_WINDOW = 3;

static void finish_watchdog_repair_cycle()
{
    const bool attempted = InterlockedExchange(
        &g_watchdog_repair_attempted,
        0) != 0;
    const ULONGLONG now = GetTickCount64();

    if (!attempted)
    {
        if (g_repair_window_started != 0 &&
            now - g_repair_window_started > REPAIR_WINDOW_MS)
        {
            g_repair_window_started = 0;
            g_repair_cycle_count = 0;
        }
        return;
    }

    if (g_repair_window_started == 0 ||
        now - g_repair_window_started > REPAIR_WINDOW_MS)
    {
        g_repair_window_started = now;
        g_repair_cycle_count = 0;
    }

    ++g_repair_cycle_count;
    if (g_repair_cycle_count >= MAX_REPAIR_CYCLES_PER_WINDOW)
    {
        if (InterlockedExchange(
                &g_runtime_repairs_quarantined,
                1) == 0)
        {
            OutputDebugStringA(
                "[neverlose] persist repair contention; runtime repairs quarantined\n");
        }
    }
}

void acquire_patch_write_lock()
{
    AcquireSRWLockExclusive(&g_patch_write_lock);
}

void release_patch_write_lock()
{
    ReleaseSRWLockExclusive(&g_patch_write_lock);
}

void thaw_patch_threads(patch_thread_freeze_state& state)
{
    for (size_t index = state.count; index > 0; --index)
    {
        suspended_patch_thread& thread = state.threads[index - 1];
        if (thread.suspended)
            ResumeThread(static_cast<HANDLE>(thread.handle));
        if (thread.handle)
            CloseHandle(static_cast<HANDLE>(thread.handle));

        thread = {};
    }

    state.count = 0;
}

bool freeze_patch_threads(patch_thread_freeze_state& state)
{
    if (state.count != 0)
        return false;

    const DWORD process_id = GetCurrentProcessId();
    const DWORD current_thread_id = GetCurrentThreadId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        thaw_patch_threads(state);
        return false;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot, &entry))
    {
        CloseHandle(snapshot);
        thaw_patch_threads(state);
        return false;
    }

    do
    {
        if (entry.th32OwnerProcessID != process_id ||
            entry.th32ThreadID == current_thread_id)
        {
            continue;
        }

        if (state.count == MAX_SUSPENDED_PATCH_THREADS)
        {
            CloseHandle(snapshot);
            thaw_patch_threads(state);
            return false;
        }

        HANDLE thread = OpenThread(
            THREAD_SUSPEND_RESUME |
                THREAD_GET_CONTEXT |
                THREAD_QUERY_INFORMATION |
                SYNCHRONIZE,
            FALSE,
            entry.th32ThreadID);
        if (!thread)
        {
            if (GetLastError() == ERROR_INVALID_PARAMETER)
                continue;

            CloseHandle(snapshot);
            thaw_patch_threads(state);
            return false;
        }

        suspended_patch_thread& slot = state.threads[state.count];
        slot.handle = thread;
        slot.instruction_pointer = 0;
        slot.suspended = false;
        ++state.count;
    }
    while (Thread32Next(snapshot, &entry));

    const DWORD enumeration_error = GetLastError();
    CloseHandle(snapshot);
    if (enumeration_error != ERROR_NO_MORE_FILES)
    {
        thaw_patch_threads(state);
        return false;
    }

    for (size_t index = 0; index < state.count; ++index)
    {
        suspended_patch_thread& thread = state.threads[index];
        const HANDLE handle = static_cast<HANDLE>(thread.handle);
        if (SuspendThread(handle) == static_cast<DWORD>(-1))
        {
            if (WaitForSingleObject(handle, 0) == WAIT_OBJECT_0)
                continue;

            thaw_patch_threads(state);
            return false;
        }
        thread.suspended = true;

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(handle, &context))
        {
            if (WaitForSingleObject(handle, 0) == WAIT_OBJECT_0)
                continue;

            thaw_patch_threads(state);
            return false;
        }

        thread.instruction_pointer =
            static_cast<uintptr_t>(context.Eip);
    }

    return true;
}

bool patch_threads_are_safe(
    const patch_thread_freeze_state& state,
    const patch_code_range* ranges,
    size_t range_count)
{
    if (range_count && !ranges)
        return false;

    for (size_t thread_index = 0;
         thread_index < state.count;
         ++thread_index)
    {
        const suspended_patch_thread& thread =
            state.threads[thread_index];
        if (!thread.suspended)
            continue;

        for (size_t range_index = 0;
             range_index < range_count;
             ++range_index)
        {
            const uintptr_t begin = ranges[range_index].address;
            const size_t size = ranges[range_index].size;
            const uintptr_t end = begin + size;
            if (!begin || !size || end < begin)
                return false;

            if (thread.instruction_pointer >= begin &&
                thread.instruction_pointer < end)
            {
                return false;
            }
        }
    }

    return true;
}

bool run_persist_patch_transaction_locked(
    const patch_code_range* ranges,
    size_t range_count,
    persist_fn_t writer)
{
    if (!writer)
        return false;

    if (InterlockedCompareExchange(
            &g_watchdog_callback_active,
            0,
            0) != 0)
    {
        if (InterlockedCompareExchange(
                &g_runtime_repairs_quarantined,
                0,
                0) != 0)
        {
            return false;
        }
        InterlockedExchange(&g_watchdog_repair_attempted, 1);
    }

    patch_thread_freeze_state state{};
    if (!freeze_patch_threads(state))
        return false;

    if (!patch_threads_are_safe(state, ranges, range_count))
    {
        thaw_patch_threads(state);
        return false;
    }

    bool completed = false;
    __try
    {
        writer();
        completed = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        completed = false;
    }

    thaw_patch_threads(state);
    return completed;
}

void register_persist_callback(persist_fn_t fn)
{
    if (!fn)
        return;

    for (int i = 0; i < g_callback_count; ++i)
    {
        if (g_callbacks[i] == fn)
            return;
    }

    if (g_callback_count < MAX_PERSIST_CALLBACKS)
        g_callbacks[g_callback_count++] = fn;
}

// ---------------------------------------------------------------------------
// Watchdog thread — single thread replaces 4-5 individual threads
// ---------------------------------------------------------------------------
static DWORD WINAPI persist_watchdog(PVOID parameter)
{
    const HANDLE stop_event = static_cast<HANDLE>(parameter);
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT)
        return 0;

    for (;;)
    {
        InterlockedExchange(&g_watchdog_repair_attempted, 0);
        InterlockedExchange(&g_watchdog_callback_active, 1);
        acquire_patch_write_lock();
        for (int i = 0; i < g_callback_count; i++)
        {
            __try { g_callbacks[i](); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        release_patch_write_lock();
        InterlockedExchange(&g_watchdog_callback_active, 0);
        finish_watchdog_repair_cycle();

        if (WaitForSingleObject(
                stop_event,
                WATCHDOG_INTERVAL_MS) != WAIT_TIMEOUT)
            break;
    }

    return 0;
}

// ---------------------------------------------------------------------------
// start_persist_watchdog — spawn the single thread
// ---------------------------------------------------------------------------
void start_persist_watchdog()
{
    if (InterlockedCompareExchange(&g_watchdog_started, 1, 0) != 0)
        return;

    InterlockedExchange(&g_watchdog_callback_active, 0);
    InterlockedExchange(&g_watchdog_repair_attempted, 0);
    InterlockedExchange(&g_runtime_repairs_quarantined, 0);
    g_repair_window_started = 0;
    g_repair_cycle_count = 0;

    g_watchdog_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_watchdog_stop_event)
    {
        InterlockedExchange(&g_watchdog_started, 0);
        return;
    }

    g_watchdog_thread = CreateThread(
        nullptr, 0, persist_watchdog, g_watchdog_stop_event, 0, nullptr);
    if (!g_watchdog_thread)
    {
        CloseHandle(g_watchdog_stop_event);
        g_watchdog_stop_event = nullptr;
        InterlockedExchange(&g_watchdog_started, 0);
    }
    else
    {
        SetThreadPriority(
            g_watchdog_thread,
            THREAD_PRIORITY_BELOW_NORMAL);
    }
}

void request_persist_watchdog_stop()
{
    const HANDLE stop_event = g_watchdog_stop_event;
    if (stop_event)
        SetEvent(stop_event);
}
