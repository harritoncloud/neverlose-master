#include "HookFn.h"

static void FixRels(PVOID Address, PVOID Trampoline)
{
    BYTE* og = static_cast<BYTE*>(Address);
    INT32 absolute = 0;

    switch (*og)
    {
    case 0xE8:
    case 0xE9:
        absolute = reinterpret_cast<INT32>(og) +
            *reinterpret_cast<INT32*>(og + 1) + 5;

        *reinterpret_cast<INT32*>(
            static_cast<BYTE*>(Trampoline) + 1
            ) = absolute - reinterpret_cast<INT32>(Trampoline) - 5;
        break;

    case 0x0F:
        if (og[1] >= 0x80 && og[1] < 0x90)
        {
            absolute = reinterpret_cast<INT32>(og) +
                *reinterpret_cast<INT32*>(og + 2) + 6;

            *reinterpret_cast<INT32*>(
                static_cast<BYTE*>(Trampoline) + 2
                ) = absolute - reinterpret_cast<INT32>(Trampoline) - 6;
        }
        break;

    default:
        break;
    }
}

NTSTATUS HookFn(
    void* Dst,
    void* Src,
    SIZE_T NopBytes,
    void** TrampOut,
    size_t TrampOffset)
{
    if (!Dst || !Src)
        return STATUS_INVALID_PARAMETER;

    const SIZE_T regsize = 5 + NopBytes;
    // Offset equal to regsize is valid: PEB hooks need a jump-only trampoline.
    if (TrampOut && TrampOffset > regsize)
        return STATUS_INVALID_PARAMETER;

    if (TrampOut)
        *TrampOut = nullptr;

    INT32 rel32 =
        static_cast<INT32>(
            static_cast<BYTE*>(Src) -
            static_cast<BYTE*>(Dst) - 5
            );

    DWORD OldProto = 0;
    PVOID baseaddr = Dst;
    SIZE_T localRegSize = regsize;

    NTSTATUS status = NtProtectVirtualMemory(
        NtCurrentProcess(),
        &baseaddr,
        &localRegSize,
        PAGE_EXECUTE_READWRITE,
        &OldProto
    );

    if (!NT_SUCCESS(status))
        return status;

    auto restore_protection = [&]() {
        PVOID restore_base = Dst;
        SIZE_T restore_size = regsize;
        DWORD ignored = 0;
        return NtProtectVirtualMemory(
            NtCurrentProcess(),
            &restore_base,
            &restore_size,
            OldProto,
            &ignored
        );
    };

    if (TrampOut)
    {
        PVOID pTramp = nullptr;

        size_t tramp_copy_size = regsize - TrampOffset;
        SIZE_T TrampSizeLocal = tramp_copy_size + 5;

        status = NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &pTramp,
            0,
            &TrampSizeLocal,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );

        if (!NT_SUCCESS(status))
        {
            restore_protection();
            return status;
        }

        memcpy(
            pTramp,
            static_cast<char*>(Dst) + TrampOffset,
            tramp_copy_size
        );

        if (tramp_copy_size)
        {
            FixRels(
                static_cast<char*>(Dst) + TrampOffset,
                pTramp
            );
        }

        *(static_cast<BYTE*>(pTramp) + tramp_copy_size) =
            static_cast<BYTE>(0xE9);

        *reinterpret_cast<INT32*>(
            static_cast<BYTE*>(pTramp) + tramp_copy_size + 1
            ) =
            static_cast<INT32>(
                static_cast<BYTE*>(Dst) + regsize -
                (static_cast<BYTE*>(pTramp) + tramp_copy_size) - 5
                );

        status = NtFlushInstructionCache(
            NtCurrentProcess(),
            pTramp,
            TrampSizeLocal
        );
        if (!NT_SUCCESS(status))
        {
            PVOID free_base = pTramp;
            SIZE_T free_size = 0;
            NtFreeVirtualMemory(
                NtCurrentProcess(), &free_base, &free_size, MEM_RELEASE);
            restore_protection();
            return status;
        }

        PVOID tramp_base = pTramp;
        SIZE_T tramp_size = TrampSizeLocal;
        DWORD tramp_old_protection = 0;
        status = NtProtectVirtualMemory(
            NtCurrentProcess(),
            &tramp_base,
            &tramp_size,
            PAGE_EXECUTE_READ,
            &tramp_old_protection);
        if (!NT_SUCCESS(status))
        {
            PVOID free_base = pTramp;
            SIZE_T free_size = 0;
            NtFreeVirtualMemory(
                NtCurrentProcess(), &free_base, &free_size, MEM_RELEASE);
            restore_protection();
            return status;
        }

        *TrampOut = pTramp;
    }

    *static_cast<BYTE*>(Dst) = static_cast<BYTE>(0xE9);

    *reinterpret_cast<INT32*>(
        static_cast<BYTE*>(Dst) + 1
        ) = rel32;

    if (NopBytes)
        memset(
            static_cast<char*>(Dst) + 5,
            0x90,
            NopBytes
        );

    status = restore_protection();
    if (!NT_SUCCESS(status))
        return status;

    return NtFlushInstructionCache(
        NtCurrentProcess(),
        Dst,
        regsize
    );
}
