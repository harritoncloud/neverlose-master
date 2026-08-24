# Safe Optimization Audit

Date: 2026-07-28
Configuration: Release, Win32/x86

## Safety Baseline

- Pre-change backup: `backups/20260728-195801-pre-full-optimization`
- DLL manifest: `backups/20260728-195801-pre-full-optimization/SHA256SUMS.csv`
- Source manifest: `backups/20260728-195801-pre-full-optimization/SOURCE_SHA256SUMS.csv`
- Verified backup contents: 5 DLL files and 68 source/project files.
- Missing backup files: 0.
- Backup hash mismatches: 0.
- Existing DLL files were not deleted.
- The game, injector, and bundled server were not launched during validation.

## Preserved Invariants

- Hard-coded target addresses and hook ABI were not changed.
- Naked assembly hooks were not rewritten.
- Persist intervals remain 16 ms and 10 ms where previously configured.
- Backtrack lerp remains disabled because it breaks nade prediction.
- Nadewarn remains fully transparent with radius `29.7f` and the restored
  270-degree arc constants.
- Pending DLL deployment now keeps the pending DLL instead of deleting it.

## C++ Review

| File | Status | Result |
| --- | --- | --- |
| `injector/main.cpp` | Modified | Keeps pending DLL backups, removes an unused load, hardens resource/remote-memory handling, and resolves `LoadLibraryA` relative to its remote owner module. |
| `neverlose/crypto_capture.cpp` | Reviewed | ABI-sensitive capture hook retained unchanged. |
| `neverlose/entry.cpp` | Modified | Removes dead context code and validates thread resume. |
| `neverlose/FindPattern.cpp` | Modified | Adds argument checks, one-byte fast path, and correct scan bounds. |
| `neverlose/fix_anim_layers_preserve.cpp` | Reviewed | Naked dispatch hook and retry behavior retained unchanged. |
| `neverlose/fix_backtrack_lerp.cpp` | Modified | Skips unchanged NOP ranges and validates page protection. |
| `neverlose/fix_cvars.cpp` | Modified | Caches duplicate ConVar lookups and validates interfaces. |
| `neverlose/fix_dump.cpp` | Modified | Validates scratch allocation before publishing pointers. |
| `neverlose/fix_extrap_ticks.cpp` | Modified | Skips unchanged writes and restores page protection safely. |
| `neverlose/fix_hitscan.cpp` | Modified | Checks full NOP ranges and avoids redundant page changes. |
| `neverlose/fix_imports.cpp` | Modified | Caches modules and duplicate imports, including ordinal-safe keys. |
| `neverlose/fix_interfaces.cpp` | Modified | Caches module factories and duplicate interface instances. |
| `neverlose/fix_lerp_disable.cpp` | Modified | Checks complete ranges and batches only required writes. |
| `neverlose/fix_menu_extra.cpp` | Modified | Avoids unchanged writes, validates protection, cleans partial allocations, and seals code caves RX. |
| `neverlose/fix_persist.cpp` | Modified | Deduplicates callbacks and prevents duplicate watchdog threads. |
| `neverlose/fix_records_size.cpp` | Modified | Skips unchanged writes and restores page protection safely. |
| `neverlose/fix_signatures.cpp` | Modified | Caches module metadata and duplicate pattern scans. |
| `neverlose/fun_stuff.cpp` | Modified | Preserves legacy notes under `#if 0` so accidental compilation is safe. |
| `neverlose/Hide.cpp` | Modified | Skips already-applied patches and validates page protection. |
| `neverlose/HideLegit.cpp` | Modified | Restores protection with stable base/size values. |
| `neverlose/HookFn.cpp` | Modified | Validates inputs, handles failures, flushes caches, and seals generated trampolines RX. |
| `neverlose/main.cpp` | Reviewed | Loader-thread ordering and module wait retained unchanged. |
| `neverlose/mem_dispatcher.cpp` | Modified | Validates requests and Detours transactions; scans the actual PE image instead of 2 GB. |
| `neverlose/nadewarn.cpp` | Modified | Skips unchanged writes, prevents duplicate threads, repairs full arc patches, and seals code caves RX. |
| `neverlose/neverlose.cpp` | Modified | Uses bounded formatting and validates embedded resource sizes. |
| `neverlose/Requestor.cpp` | Modified | Removes route allocation churn, handles partial reads, and bounds debug formatting. |
| `neverlose/setup_hooks.cpp` | Modified | Removes a busy yield, avoids unaligned logo reads, and validates critical hooks. |
| `neverlose/sha256.cpp` | Modified | Aligns constants and uses the native byte-swap intrinsic. |
| `neverlose/spoof.cpp` | Modified | Prevents disk-data overread, validates buffers, and validates hook targets/results. |
| `neverlose/spoof_cpuid.cpp` | Modified | Validates and seals the trampoline arena. |
| `neverlose/spoof_kusd.cpp` | Modified | Avoids failed-trampoline writes and seals executable memory. |
| `neverlose/spoof_peb.cpp` | Modified | Validates and seals the trampoline arena. |
| `neverlose/VEH.cpp` | Modified | Validates exception context and VEH installation. |

Total C++ files reviewed: 33
Modified: 30
Reviewed without source changes: 3

## Second Pass

- Backup: `backups/20260728-232533-pre-cpp-pass2`.
- `Requestor.cpp` no longer opens and writes `nl_requestor_debug.log` for every
  HTTP request in Release builds. Diagnostics remain available with
  `NLR_ENABLE_REQUESTOR_DIAGNOSTICS`.
- `fix_interfaces.cpp` now rejects invalid module/interface descriptors before
  cache lookup.
- `fix_imports.cpp` now validates and snapshots import descriptors before cache
  lookup while retaining name and ordinal compatibility.
- `nadewarn.cpp` validates both module handles before resolving
  `CreateInterface`; visual patch addresses and constants are unchanged.
- `main.cpp` and `entry.cpp` now describe or document their intentional native
  thread entry contracts for static analysis without changing their ABI.
- The initial full-project MSVC analysis reported five diagnostics. The final
  full-project result is zero defects.
- The Release DLL decreased from 55,740,416 to 55,727,104 bytes.

## Fakelag Limits

- Backup: `backups/20260729-173733-pre-fakelag16`.
- `fix_fakelag_limits.cpp` overrides the Neverlose read at `0x4159556D` with
  `sv_maxusrcmdprocessticks = 17`, which permits 16 choked ticks.
- Fake Duck retains its independent comparison at `0x413632BF` with threshold
  13, so it sends on the 14th choked tick instead of inheriting the 16-tick
  general limit.
- Both patch sites validate their surrounding opcodes before writing and use
  the existing persist watchdog; no additional thread is created.
- Clean `Release|Win32` rebuild succeeded and full-project MSVC analysis
  reported zero defects.

## Supporting Changes

- `neverlose/ArenaAllocator.h`: capacity checks and RX sealing.
- `neverlose/logger.h`: true no-op path when logging is disabled.
- `neverlose/neverlose.vcxproj`: explicit safe Release speed settings and unused-section elimination.
- `injector/injector.vcxproj`: explicit safe Release speed settings and unused-section elimination.

## First-Pass Validation

- Clean `Release|Win32` rebuild succeeded.
- Injector: all 319 functions rebuilt.
- DLL: all 592 functions rebuilt.
- `dumpbin` confirms x86 for both outputs and DLL type for `neverlose.dll`.
- Nadewarn constants `40278D36h`, `3F91745Dh`, and `4016CBE4h` are present in final disassembly.
- `fun_stuff.cpp` compiles independently as an inert translation unit.
- The `HookFn` regression test covers `TrampOffset == patch size`, which is
  required by every PEB hook. It returns the expected hook and trampoline
  values and confirms RX trampoline protection.
- No runtime launch test was performed, as requested.

## Crash Regression

- The first optimized build rejected `TrampOffset == patch size`.
- `spoof_peb.cpp` intentionally uses that value to create jump-only
  trampolines, so all PEB hooks were skipped.
- `HookFn` now rejects only offsets greater than the patch size and avoids
  relocation parsing when the copy length is zero.
- The known-working DLL remains at `Release/neverlose.dll`.
- The corrected optimized candidate is stored separately and backed up.

## Current Final Artifacts

- `Release/neverlose.dll`
- `artifacts/fakelag16-fakeduck14-20260729-174016/neverlose.dll`
- `backups/20260729-173733-pre-fakelag16/neverlose.dll`
- Final SHA-256:
  `3D52663F8D80C18AF2F3DDFED22149F97E61FEFFBF44AF4FC0A8861C93324C19`
- Final binary is PE32/x86 and imports `TerminateProcess`.
- Nadewarn alpha-zero sequence is present once, `29.7f` is used once, and
  `31.0f` is not used as an instruction immediate.
- The synchronous final-exit bridge remains intact.
- The game, injector, and bundled server were not launched.
