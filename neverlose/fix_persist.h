#pragma once

// ============================================================
//  fix_persist.h
//
//  Unified persist watchdog — replaces per-fix persist threads
//  with a single thread that runs all check-before-write logic
//  in one rate-limited loop. Benefits:
//    - 1 thread instead of 5 (less detectable, less overhead)
//    - 250ms idle checks instead of polling every frame
//    - All patches checked + applied atomically per iteration
//    - Runtime repair circuit breaker stops competing writers
//
//  Usage: each fix module calls register_persist_callback()
//  during init. start_persist_watchdog() spawns the thread.
// ============================================================

#include <cstddef>
#include <cstdint>
#include <array>

// Max registered callbacks
static constexpr int MAX_PERSIST_CALLBACKS = 16;

// Callback type: void function that checks + applies its patches
typedef void (*persist_fn_t)();

struct patch_code_range
{
    uintptr_t address;
    size_t size;
};

static constexpr size_t MAX_SUSPENDED_PATCH_THREADS = 512;

struct suspended_patch_thread
{
    void* handle = nullptr;
    uintptr_t instruction_pointer = 0;
    bool suspended = false;
};

struct patch_thread_freeze_state
{
    std::array<
        suspended_patch_thread,
        MAX_SUSPENDED_PATCH_THREADS> threads{};
    size_t count = 0;
};

// Register a persist callback (called during fix init)
void register_persist_callback(persist_fn_t fn);

// Serialize executable-code writes performed by the persist watchdog and
// feature-specific recovery transactions.
void acquire_patch_write_lock();
void release_patch_write_lock();

// Freeze every other process thread without dynamic allocation. The state is
// always cleaned internally on a failed freeze.
bool freeze_patch_threads(patch_thread_freeze_state& state);
bool patch_threads_are_safe(
    const patch_thread_freeze_state& state,
    const patch_code_range* ranges,
    size_t range_count);
void thaw_patch_threads(patch_thread_freeze_state& state);

// Called only from a registered callback while the watchdog owns the shared
// patch-write lock. The writer runs with other threads suspended and is
// skipped if a thread is stopped inside one of the supplied code ranges.
bool run_persist_patch_transaction_locked(
    const patch_code_range* ranges,
    size_t range_count,
    persist_fn_t writer);

// Spawn the unified watchdog thread (called once from setup_hooks)
void start_persist_watchdog();

// Non-blocking shutdown signal. Safe to call while the process is detaching.
void request_persist_watchdog_stop();
