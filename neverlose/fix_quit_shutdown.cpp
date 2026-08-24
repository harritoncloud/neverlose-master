#include "fix_quit_shutdown.h"

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>

namespace
{
constexpr std::uintptr_t kFinalShutdownRoutineRva = 0x294B70;
constexpr std::uintptr_t kHostShutdownCallRva = 0x294B8A;

constexpr std::array<std::uint8_t, 5> kFinalShutdownPreamble = {
    0x55, 0x8B, 0xEC, 0x51, 0x51
};

constexpr std::array<std::uint8_t, 5> kHostShutdownCall = {
    0xE8, 0x01, 0x9F, 0xF9, 0xFF
};

constexpr std::array<std::uint8_t, 5> kPreviousNops = {
    0x90, 0x90, 0x90, 0x90, 0x90
};

void __cdecl final_shutdown_bridge()
{
    // ExitProcess can terminate helper threads before DLL detach and then
    // deadlock while unloading. Terminate synchronously before that phase.
    TerminateProcess(GetCurrentProcess(), 0);
}

bool make_bridge_call(
    const std::uint8_t* call_site,
    std::array<std::uint8_t, 5>& patch)
{
    const auto target = static_cast<std::int64_t>(
        reinterpret_cast<std::uintptr_t>(&final_shutdown_bridge));
    const auto next_instruction = static_cast<std::int64_t>(
        reinterpret_cast<std::uintptr_t>(call_site + patch.size()));
    const std::int64_t relative = target - next_instruction;

    if (relative < std::numeric_limits<std::int32_t>::min() ||
        relative > std::numeric_limits<std::int32_t>::max())
    {
        return false;
    }

    patch = { 0xE8, 0, 0, 0, 0 };
    const auto relative32 = static_cast<std::int32_t>(relative);
    std::memcpy(patch.data() + 1, &relative32, sizeof(relative32));
    return true;
}

bool write_code(void* destination, const void* source, std::size_t size)
{
    DWORD old_protection = 0;
    if (!VirtualProtect(
            destination,
            size,
            PAGE_EXECUTE_READWRITE,
            &old_protection))
    {
        return false;
    }

    std::memcpy(destination, source, size);
    const BOOL flushed = FlushInstructionCache(
        GetCurrentProcess(), destination, size);

    DWORD ignored = 0;
    const BOOL restored = VirtualProtect(
        destination, size, old_protection, &ignored);
    return flushed && restored;
}
}

bool apply_quit_shutdown_fix()
{
    const HMODULE engine = GetModuleHandleW(L"engine.dll");
    if (!engine)
        return false;

    auto* const image = reinterpret_cast<std::uint8_t*>(engine);

    __try
    {
        const auto* const dos =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew <= 0 ||
            dos->e_lfanew >= 0x100000)
        {
            return false;
        }

        const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            image + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.SizeOfImage <
                kHostShutdownCallRva + kHostShutdownCall.size())
        {
            return false;
        }

        auto* const shutdown_routine = image + kFinalShutdownRoutineRva;
        auto* const call_site = image + kHostShutdownCallRva;
        std::array<std::uint8_t, 5> bridge_call = {};

        if (std::memcmp(
                shutdown_routine,
                kFinalShutdownPreamble.data(),
                kFinalShutdownPreamble.size()) != 0)
        {
            return false;
        }

        if (!make_bridge_call(call_site, bridge_call))
            return false;

        if (std::memcmp(
                call_site, bridge_call.data(), bridge_call.size()) == 0)
        {
            return true;
        }

        const bool has_original_call = std::memcmp(
                call_site,
                kHostShutdownCall.data(),
                kHostShutdownCall.size()) == 0;
        const bool has_previous_nops = std::memcmp(
                call_site,
                kPreviousNops.data(),
                kPreviousNops.size()) == 0;
        if (!has_original_call && !has_previous_nops)
        {
            return false;
        }

        return write_code(
            call_site, bridge_call.data(), bridge_call.size());
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}
