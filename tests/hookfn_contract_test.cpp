#include "../neverlose/HookFn.h"

#include <cstdio>
#include <cstring>

static int __cdecl replacement()
{
    return 7;
}

int main()
{
    auto* target = static_cast<unsigned char*>(VirtualAlloc(
        nullptr,
        32,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!target)
        return 1;

    std::memset(target, 0x90, 6);
    const unsigned char continuation[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
        0xC3                          // ret
    };
    std::memcpy(target + 6, continuation, sizeof(continuation));

    void* trampoline = nullptr;
    const NTSTATUS status = HookFn(
        target,
        reinterpret_cast<void*>(&replacement),
        1,
        &trampoline,
        6);
    if (!NT_SUCCESS(status) || !trampoline)
    {
        std::printf("HookFn failed: 0x%08lX\n", status);
        VirtualFree(target, 0, MEM_RELEASE);
        return 2;
    }

    const int hooked_result = reinterpret_cast<int(__cdecl*)()>(target)();
    const int trampoline_result =
        reinterpret_cast<int(__cdecl*)()>(trampoline)();

    MEMORY_BASIC_INFORMATION info{};
    const bool queried =
        VirtualQuery(trampoline, &info, sizeof(info)) == sizeof(info);
    const DWORD protection = queried ? info.Protect & 0xFF : 0;
    const bool trampoline_is_rx = protection == PAGE_EXECUTE_READ;

    std::printf(
        "status=0x%08lX hook=%d trampoline=%d protection=0x%lX\n",
        status,
        hooked_result,
        trampoline_result,
        protection);

    VirtualFree(trampoline, 0, MEM_RELEASE);
    VirtualFree(target, 0, MEM_RELEASE);

    return hooked_result == 7 &&
        trampoline_result == 42 &&
        trampoline_is_rx
        ? 0
        : 3;
}
