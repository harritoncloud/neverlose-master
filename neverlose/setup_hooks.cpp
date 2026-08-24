#define WIN32_NO_STATUS
#include <winsock2.h>
#include <Windows.h>

#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "neverlose.h"
#include "HookFn.h"
#include "neverlosesdk.hpp"

#include "nadewarn.h"
#include "fix_records_size.h"
#include "fix_lerp_disable.h"
#include "fix_extrap_ticks.h"
#include "fix_backtrack_lerp.h"
#include "fix_anim_layers_preserve.h"
#include "fix_persist.h"
#include "fix_rage_records.h"
#include "fix_quit_shutdown.h"
#include "fix_menu_extra.h"
#include "nl_anim_hook.h"
#include "Hide.h"
#include "HideLegit.h"

static void set_nl_logo(const char* name)
{
    if (!name)
        return;

    uint32_t words[4] = {};
    const size_t name_length = strlen(name);
    const size_t len =
        name_length < sizeof(words) ? name_length : sizeof(words);
    memcpy(words, name, len);

    *reinterpret_cast<uint32_t*>(0x4160555E) = words[0] ^ 0xD7E76FF9;
    *reinterpret_cast<uint32_t*>(0x41605558) = words[1] ^ 0xBA5A7287;
    *reinterpret_cast<uint32_t*>(0x41605576) = words[2] ^ 0x2D725D76;
    *reinterpret_cast<uint32_t*>(0x41605570) = words[3] ^ 0x4066CCAE;
}

HMODULE WaitForSingleModule(const char* module_name)
{
    HMODULE mod = nullptr;

    while (!(mod = GetModuleHandleA(module_name)))
    {
        Sleep(10);
    }

    return mod;
}

void WSAAPI ProceedGetAddrInfo(
    PVOID retaddr,
    PCSTR* ppNodeName,
    PCSTR* ppServiceName)
{
    if (g_neverlose.in_range(retaddr))
    {
        *ppNodeName = "127.0.0.1";
        *ppServiceName = "30030";
    }
}

void* getaddr_tram = nullptr;

INT __declspec(naked) WSAAPI hkgetaddrinfo(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA* ppResult)
{
    __asm
    {
        push ebp
        mov ebp, esp

        lea eax, [ebp + 12]
        push eax

        lea eax, [ebp + 8]
        push eax

        push[ebp + 4]
        call ProceedGetAddrInfo

        mov esp, ebp
        pop ebp

        push ebp
        mov ebp, esp
        jmp getaddr_tram
    }
}

void __fastcall performmenu(neverlosesdk::gui::Menu& menu)
{
    menu.IsOpen = !menu.IsOpen;

    if (!menu.IsOpen)
    {
        auto config_entry =
            reinterpret_cast<PDWORD>(*reinterpret_cast<DWORD*>(0x425006F0));

        if (config_entry)
        {
            if (config_entry[39] == static_cast<DWORD>(-1))
                config_entry[39] = config_entry[38];

            reinterpret_cast<void(__thiscall*)(PDWORD)>(0x4153DFD0)(config_entry);
        }
    }
}

void neverlose::setup_hooks()
{
    set_nl_logo("patchwin.cc");

    const bool quit_fix_installed = apply_quit_shutdown_fix();
    ENTER_LOGGER(logman)
        << "[FIX] Synchronous final process exit "
        << (quit_fix_installed ? "installed.\n" : "not installed.\n");

    HMODULE ws2 = WaitForSingleModule("ws2_32.dll");
    FARPROC getaddrinfo = GetProcAddress(ws2, "getaddrinfo");
    if (!getaddrinfo)
        panic("Failed to find getaddrinfo!");

    getaddr_tram = reinterpret_cast<PBYTE>(getaddrinfo) + 5;
    NTSTATUS status = HookFn(getaddrinfo, hkgetaddrinfo, 0);
    if (!NT_SUCCESS(status))
        panic("Failed to hook getaddrinfo: 0x%08lX", status);

    status = HookFn(reinterpret_cast<PVOID>(0x415E9086), performmenu, 0);
    if (!NT_SUCCESS(status))
        panic("Failed to hook menu toggle 1: 0x%08lX", status);

    status = HookFn(reinterpret_cast<PVOID>(0x41609C80), performmenu, 0);
    if (!NT_SUCCESS(status))
        panic("Failed to hook menu toggle 2: 0x%08lX", status);

    setup_nadewarn();

    // Keep the BT unlocks atomic and fail closed on unknown image bytes.
    const bool history_unlock_installed = apply_records_size_fix();
    ENTER_LOGGER(logman)
        << "[FIX] BT history threshold unlock "
        << (history_unlock_installed ? "installed.\n" : "not installed.\n");

    const bool ratio_unlock_installed = apply_bt_ratio_unlock();
    ENTER_LOGGER(logman)
        << "[FIX] BT ratio unlock "
        << (ratio_unlock_installed ? "installed.\n" : "not installed.\n");

    apply_extrap_ticks_fix();    // Native extrapolation budget = 2 ticks
    apply_anim_layers_preserve();// Preserve layer 10/11 weight and cycle
    const bool anim_hook_installed = install_nl_anim_hook();
    ENTER_LOGGER(logman)
        << "[HOOK] Native animation inspection hook "
        << (anim_hook_installed ? "installed.\n" : "not installed.\n");
    const bool rage_record_patches_installed = apply_rage_record_patches();
    ENTER_LOGGER(logman)
        << "[FIX] Rage record safe profile "
        << (rage_record_patches_installed
            ? "installed.\n"
            : "not installed.\n");
    // Hitscan patch disabled: previous version overwrote a partial instruction.
    //apply_backtrack_lerp_fix(); // Disabled — breaks nade prediction

    apply_menu_extra();          // Extra — branding, about, profile, chat, URLs
    apply_Hide();                // Native port of Hide#7.lua
    apply_HideLegit();           // Hide the Legit tab

    // Start the single unified persist thread (replaces 5 individual threads)
    start_persist_watchdog();
}
