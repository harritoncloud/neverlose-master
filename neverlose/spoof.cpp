#include "neverlose.h"
#include "HookFn.h"
#include "diskpas.h"
#include <iphlpapi.h>
#include <algorithm>
#include <array>
#include <cstring>

#ifndef IOCTL_STORAGE_QUERY_PROPERTY
#define IOCTL_STORAGE_QUERY_PROPERTY 0x002D1400
#endif

#ifndef SMART_RCV_DRIVE_DATA
#define SMART_RCV_DRIVE_DATA 0x0007C088
#endif

struct DeviceIoStack
{
    PVOID Retaddr;
    HANDLE FileHandle;
    HANDLE Event;
    PIO_APC_ROUTINE ApcRoutine;
    PVOID ApcContext;
    PIO_STATUS_BLOCK IoStatusBlock;
    ULONG IoControlCode;
    PVOID InputBuffer;
    ULONG InputBufferLength;
    PVOID OutputBuffer;
    ULONG OutputBufferLength;
};

BOOL NTAPI HandleDeviceIo(DeviceIoStack* args)
{
    if (!args)
        return FALSE;

    if (g_neverlose.in_range(args->Retaddr))
    {
        if (args->IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY ||
            args->IoControlCode == SMART_RCV_DRIVE_DATA)
        {
            if (args->OutputBufferLength && !args->OutputBuffer)
                return FALSE;

            const size_t copy_size = std::min<size_t>(
                args->OutputBufferLength, sizeof(diskpas_rawData));
            if (copy_size)
                memcpy(args->OutputBuffer, diskpas_rawData, copy_size);
            if (args->OutputBufferLength > copy_size)
            {
                memset(
                    static_cast<PBYTE>(args->OutputBuffer) + copy_size,
                    0,
                    args->OutputBufferLength - copy_size);
            }

            return TRUE;
        }
    }

    return FALSE;
}

void* deviceio_tram = nullptr;

NTSTATUS __declspec(naked) NTAPI hkNtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength)
{
    __asm
    {
        push ebp
        mov ebp, esp
        lea eax, [ebp + 4]
        push eax
        call HandleDeviceIo
        test eax, eax
        mov esp, ebp
        pop ebp
        je callog
        ret 0x28

        callog:
        mov eax, 0x001B0007
            jmp deviceio_tram
    }
}

struct adapter_t
{
    const char* Name;
    BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
};

constexpr auto g_spoofed_adapters = std::to_array<adapter_t>
({
    { "{8AD76F14-7DA1-4786-9706-2A3E545BCADD}", { 0xD8, 0x43, 0xAE, 0x96, 0x4E, 0xD8, 0x00, 0x00 } },
    { "{D584346C-AF4E-47CC-B402-B9FB34A569BC}", { 0x7A, 0x79, 0x19, 0x12, 0x93, 0xC3, 0x00, 0x00 } },
    { "{88A9926E-8033-4628-9A18-C20AB9B2A574}", { 0x2C, 0x98, 0x11, 0x1A, 0xD2, 0x24, 0x00, 0x00 } },
    { "{44E3B917-A89B-48C5-B871-B72158E6A845}", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "{A06F2639-34F6-4DBB-B736-5C8CB14D3B10}", { 0x2C, 0x98, 0x11, 0x1A, 0xD2, 0x23, 0x00, 0x00 } },
    { "{423DC722-6046-4D7E-93A1-619D9663BEE2}", { 0x2E, 0x98, 0x11, 0x1A, 0xF2, 0x03, 0x00, 0x00 } },
    { "{30604C72-5277-49DB-ADF2-4F8F1AC4A893}", { 0x2E, 0x98, 0x11, 0x1A, 0xE2, 0x13, 0x00, 0x00 } },
    });

void* adapterstram = nullptr;

ULONG WINAPI hkGetAdaptersInfo(
    PIP_ADAPTER_INFO AdapterInfo,
    PULONG SizePointer)
{
    if (g_neverlose.in_range(_ReturnAddress()))
    {
        if (!SizePointer)
            return ERROR_INVALID_PARAMETER;

        constexpr ULONG adapter_count =
            static_cast<ULONG>(g_spoofed_adapters.size());

        constexpr ULONG required_size =
            sizeof(IP_ADAPTER_INFO) * adapter_count;

        if (*SizePointer < required_size)
        {
            *SizePointer = required_size;
            return ERROR_BUFFER_OVERFLOW;
        }

        if (!AdapterInfo)
            return ERROR_INVALID_PARAMETER;

        memset(AdapterInfo, 0, required_size);

        for (size_t i = 0; i < g_spoofed_adapters.size(); i++)
        {
            AdapterInfo[i].Next =
                (i == g_spoofed_adapters.size() - 1)
                ? nullptr
                : &AdapterInfo[i + 1];

            AdapterInfo[i].ComboIndex = 0;
            AdapterInfo[i].Index = static_cast<DWORD>(i + 1);
            AdapterInfo[i].Type = MIB_IF_TYPE_ETHERNET;
            AdapterInfo[i].DhcpEnabled = FALSE;
            AdapterInfo[i].HaveWins = FALSE;
            AdapterInfo[i].AddressLength = 6;

            strcpy_s(
                AdapterInfo[i].Description,
                sizeof(AdapterInfo[i].Description),
                "Intel(R) Ethernet Connection");
            strcpy_s(
                AdapterInfo[i].IpAddressList.IpAddress.String,
                sizeof(AdapterInfo[i].IpAddressList.IpAddress.String),
                "192.168.0.1");
            strcpy_s(
                AdapterInfo[i].IpAddressList.IpMask.String,
                sizeof(AdapterInfo[i].IpAddressList.IpMask.String),
                "255.255.255.0");
            strcpy_s(
                AdapterInfo[i].AdapterName,
                sizeof(AdapterInfo[i].AdapterName),
                g_spoofed_adapters[i].Name);

            memcpy(
                AdapterInfo[i].Address,
                g_spoofed_adapters[i].Address,
                MAX_ADAPTER_ADDRESS_LENGTH
            );
        }

        return ERROR_SUCCESS;
    }

    return reinterpret_cast<decltype(&GetAdaptersInfo)>(
        adapterstram
        )(AdapterInfo, SizePointer);
}

void neverlose::spoof()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        panic("Failed to find ntdll.dll for spoof hooks!");

    FARPROC ntdevicefile =
        GetProcAddress(ntdll, "NtDeviceIoControlFile");
    if (!ntdevicefile)
        panic("Failed to find NtDeviceIoControlFile!");

    deviceio_tram = GET_DEF_TRAM(ntdevicefile);

    NTSTATUS status = HookFn(
        ntdevicefile,
        hkNtDeviceIoControlFile,
        0
    );
    if (!NT_SUCCESS(status))
        panic("Failed to hook NtDeviceIoControlFile: 0x%08lX", status);

    HMODULE iphlpapi = GetModuleHandleW(L"iphlpapi.dll");
    if (!iphlpapi)
        iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (!iphlpapi)
        panic("Failed to find iphlpapi.dll!");

    FARPROC get_adapters_info = GetProcAddress(iphlpapi, "GetAdaptersInfo");
    if (!get_adapters_info)
        panic("Failed to find GetAdaptersInfo!");

    status = HookFn(
        get_adapters_info,
        hkGetAdaptersInfo,
        0,
        &adapterstram
    );
    if (!NT_SUCCESS(status))
        panic("Failed to hook GetAdaptersInfo: 0x%08lX", status);
}
