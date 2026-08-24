#include "internal_fixes.h"
#include "HookFn.h"

static void* capture_tram = nullptr;
static int __cdecl hkCaptureData(const void* data)
{
    reinterpret_cast<int(__cdecl*)(const void*)>(capture_tram)(data);
    memcpy((PVOID)0x424AFD88, data, 28);
    return *((DWORD*)data + 6);
}

void install_crypto_capture()
{
    HookFn((PVOID)0x41D9F3F0, hkCaptureData, 2, (PVOID*)&capture_tram);
}
