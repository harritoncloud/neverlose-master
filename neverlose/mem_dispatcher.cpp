#include "internal_fixes.h"
#include "HookFn.h"
#include "FindPattern.h"
#include <cstdio>
#include "detours.h"
#include <vector>

enum operation_t
{
    OPERATION_REGISTER_HOOK = 1,
    OPERATION_EMPLACE_HOOKS,
    OPERATION_ERASE_HOOKS,
    OPERATION_SIGSCAN = 6,
};

#pragma pack(push, 1)
struct sigscan_t
{
    PVOID64 Base;
    PVOID64 Signature;
    size_t Length;
    PVOID64 Result;
};

struct hook_t
{
    PVOID64 Address;
    PVOID64 Hook;
    PVOID64 pTrampoline;
};
#pragma pack(pop)

struct HookDesc
{
    bool IsActive;
    PVOID Address;
    PVOID Trampoline;
    PVOID Hook;
};

static auto& g_HkDesc = *reinterpret_cast<std::vector<HookDesc>*>(0x42500C44);
static bool TransactionAlive = false;
static PVOID g_originalSignonStateHook = (PVOID)0x415DCE40;
static PVOID g_signonTrampoline = nullptr;

static size_t get_scan_size(void* base)
{
    if (!base)
        return 0;

    __try
    {
        const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE &&
            dos->e_lfanew > 0 &&
            dos->e_lfanew < 0x100000)
        {
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                static_cast<const BYTE*>(base) + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE &&
                nt->OptionalHeader.SizeOfImage > 0)
            {
                return nt->OptionalHeader.SizeOfImage;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery(base, &info, sizeof(info)) ||
        info.State != MEM_COMMIT ||
        (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
    {
        return 0;
    }

    const auto* region_end =
        static_cast<const BYTE*>(info.BaseAddress) + info.RegionSize;
    return static_cast<size_t>(region_end - static_cast<const BYTE*>(base));
}

__declspec(naked) void hkSignonStateHookCallback()
{
    __asm
    {
        pushad
        pushfd
        mov eax, 0x415DEBD0
        call eax
        popfd
        popad
        jmp dword ptr [g_signonTrampoline]
    };
}

BOOL __cdecl hkMemDispatcher(operation_t type, void* ptr)
{
    BOOL result = FALSE;

    //printf("[0x%p] MemDispatcher(%s, 0x%p)", NtCurrentThreadId(), optostr[type], ptr);
    switch (type)
    {
    case OPERATION_SIGSCAN:
    {
        if (!ptr)
            break;

        auto* data = (sigscan_t*)ptr;
        const size_t scan_size = get_scan_size(data->Base);
        data->Result = FindPattern(
            data->Base,
            scan_size,
            (PBYTE)data->Signature,
            data->Length,
            0xCC,
            0);
        //printf(" -> 0x%llX", data->Result);
        result = TRUE;
    };
    break;
    case OPERATION_REGISTER_HOOK:
    {
        if (!ptr)
            break;

        if (!TransactionAlive)
        {
            if (DetourTransactionBegin() != NO_ERROR)
                break;
            if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
            {
                DetourTransactionAbort();
                break;
            }
            TransactionAlive = true;
        };

        auto* data = (hook_t*)ptr;
        PVOID pTramp = data->Address;
        if (data->Hook == (PVOID)0x415A9820 && !*((DWORD*)&data->Hook + 1)) return TRUE;
        if (data->Hook == (PVOID)0x415DCE40)
        {
            g_originalSignonStateHook = (PVOID)data->Hook;
            data->Hook = (PVOID)hkSignonStateHookCallback;
        }
        else if (data->Address == (PBYTE)GetModuleHandle(L"engine.dll") + 0xF0470) return TRUE;
        if (DetourAttachEx(&pTramp, data->Hook, (PDETOUR_TRAMPOLINE*)data->pTrampoline, NULL, NULL) == NO_ERROR)
        {
            //printf(" 0x%llX -> 0x%llX", data->Address, *(PVOID64*)data->pTrampoline);
            if (data->Hook == (PVOID)hkSignonStateHookCallback)
                g_signonTrampoline = *(PVOID*)data->pTrampoline;
            result = TRUE;
        }
        else
        {
            result = FALSE;
        }
    };
    break;
    case OPERATION_EMPLACE_HOOKS:
        if (TransactionAlive)
        {
            result = DetourTransactionCommit() == NO_ERROR;
            TransactionAlive = false;
        }
        else
            result = FALSE;
        break;
    case OPERATION_ERASE_HOOKS:
    {
        if (DetourTransactionBegin() != NO_ERROR)
            break;
        if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
        {
            DetourTransactionAbort();
            break;
        }

        bool detach_failed = false;
        for (auto& hook : g_HkDesc)
        {
            if (hook.IsActive && hook.Trampoline)
            {
                PVOID detour = hook.Hook;
                if (detour == g_originalSignonStateHook)
                    detour = (PVOID)hkSignonStateHookCallback;

                if (detour == (PVOID)hkSignonStateHookCallback)
                    g_signonTrampoline = hook.Trampoline;

                if (DetourDetach(&hook.Trampoline, detour) == NO_ERROR)
                    hook.IsActive = false;
                else
                    detach_failed = true;
            };
        };
        const LONG commit_status = DetourTransactionCommit();
        result = !detach_failed && commit_status == NO_ERROR;
    };
    break;
    default:
        break;
    };
    //printf("\n");
    return result;
};


void fix_mem_dispatcher()
{
	HookFn((PVOID)0x41DA0BA0, hkMemDispatcher, 0);
};
