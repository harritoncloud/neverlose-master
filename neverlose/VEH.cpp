#include "neverlose.h"
#include "cpuid_emulator.h"
#include "KUSER_SHARED_DATA_SPOOF.h"

void cpuid_emulator(CONTEXT* ctx)
{
    DWORD leaf = ctx->Eax;
    DWORD subleaf = ctx->Ecx;

    if (leaf < 0x80000000)
    {
        switch (leaf)
        {
        case 0x00000000:
            ctx->Eax = 0x10;
            ctx->Ebx = 0x68747541;
            ctx->Ecx = 0x444D4163;
            ctx->Edx = 0x69746E65;
            return;
        case 0x00000001:
            ctx->Eax = 0x0A60F12;
            ctx->Ebx = 0x100800;
            ctx->Ecx = 0x7ED8320B;
            ctx->Edx = 0x178BFBFF;
            return;
        case 0x00000005:
            ctx->Eax = 0x40;
            ctx->Ebx = 0x40;
            ctx->Ecx = 0x3;
            ctx->Edx = 0x11;
            return;
        case 0x00000006:
            ctx->Eax = 0x4;
            ctx->Ebx = 0x0;
            ctx->Ecx = 0x1;
            ctx->Edx = 0x0;
            return;
        case 0x00000007:
            if (subleaf == 0)
            {
                ctx->Eax = 0x1;
                ctx->Ebx = 0x0F1BF97A9;
                ctx->Ecx = 0x405FCE;
                ctx->Edx = 0x10000010;
                return;
            }
            else if (subleaf == 1)
            {
                ctx->Eax = 20;
                ctx->Ebx = 0;
                ctx->Ecx = 0;
                ctx->Edx = 0;
                return;
            }
        case 0x00000002:
        case 0x00000003:
        case 0x00000004:
        case 0x00000008:
        case 0x00000009:
        case 0x0000000A:
        case 0x0000000C:
        case 0x0000000E:
            ctx->Eax = 0;
            ctx->Ebx = 0;
            ctx->Ecx = 0;
            ctx->Edx = 0;
            return;
        case 0x0000000B:
            ctx->Eax = 0x1;
            ctx->Ebx = 0x2;
            ctx->Ecx = 0x100;
            ctx->Edx = 0x6;
            return;
        case 0x0000000D:
            ctx->Eax = 0x2E7;
            ctx->Ebx = 0x980;
            ctx->Ecx = 0x988;
            ctx->Edx = 0x0;
            return;
        case 0x0000000F:
            ctx->Eax = 0x0;
            ctx->Ebx = 0x0FF;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x2;
            return;
        case 0x00000010:
            ctx->Eax = 0x0;
            ctx->Ebx = 0x2;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        default:
            return;
        };
    }
    else
    {
        switch (leaf)
        {
        case 0x80000009:
        case 0x8000000B:
        case 0x8000000C:
        case 0x8000000D:
        case 0x8000000E:
        case 0x8000000F:
        case 0x80000010:
        case 0x80000011:
        case 0x80000012:
        case 0x80000013:
        case 0x80000014:
        case 0x80000015:
        case 0x80000016:
        case 0x80000017:
        case 0x80000018:
        case 0x8000001C:
        case 0x80000023:
        case 0x80000024:
        case 0x80000025:
        case 0x80000027:
        case 0x80000028:
            ctx->Eax = 0;
            ctx->Ebx = 0;
            ctx->Ecx = 0;
            ctx->Edx = 0;
            return;
        case 0x80000000:
            ctx->Eax = 0x80000028;
            ctx->Ebx = 0x68747541;
            ctx->Ecx = 0x444D4163;
            ctx->Edx = 0x69746E65;
            return;
        case 0x80000001:
            ctx->Eax = 0x0A60F12;
            ctx->Ebx = 0x0;
            ctx->Ecx = 0x75C237FF;
            ctx->Edx = 0x2FD3FBFF;
            return;
        case 0x80000002:
            ctx->Eax = 0x20444D41;
            ctx->Ebx = 0x657A7952;
            ctx->Ecx = 0x2037206E;
            ctx->Edx = 0x30303737;
            return;
        case 0x80000003:
            ctx->Eax = 0x2D382058;
            ctx->Ebx = 0x65726F43;
            ctx->Ecx = 0x6F725020;
            ctx->Edx = 0x73736563;
            return;
        case 0x80000004:
            ctx->Eax = 0x2020726F;
            ctx->Ebx = 0x20202020;
            ctx->Ecx = 0x20202020;
            ctx->Edx = 0x202020;
            return;
        case 0x80000005:
            ctx->Eax = 0xFF48FF40;
            ctx->Ebx = 0xFF48FF40;
            ctx->Ecx = 0x20080140;
            ctx->Edx = 0x20080140;
            return;
        case 0x80000006:
            ctx->Eax = 0x5C002200;
            ctx->Ebx = 0x6C004200;
            ctx->Ecx = 0x4006140;
            ctx->Edx = 0x1009140;
            return;
        case 0x80000007:
            ctx->Eax = 0x0;
            ctx->Ebx = 0x3B;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x6799;
            return;
        case 0x80000008:
            ctx->Eax = 0x3030;
            ctx->Ebx = 0x791EF257;
            ctx->Ecx = 0x400F;
            ctx->Edx = 0x10000;
            return;
        case 0x8000000A:
            ctx->Eax = 0x1;
            ctx->Ebx = 0x8000;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x1EBFBCFF;
            return;
        case 0x80000019:
            ctx->Eax = 0xF048F040;
            ctx->Ebx = 0xF0400000;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x8000001A:
            ctx->Eax = 0x6;
            ctx->Ebx = 0x0;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x8000001B:
            ctx->Eax = 0xBFF;
            ctx->Ebx = 0x0;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x8000001D:
            ctx->Eax = 0x4121;
            ctx->Ebx = 0x1C0003F;
            ctx->Ecx = 0x3F;
            ctx->Edx = 0x0;
            return;
        case 0x8000001E:
            ctx->Eax = 0xC;
            ctx->Ebx = 0x106;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x8000001F:
            ctx->Eax = 0x1;
            ctx->Ebx = 0xB3;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x80000020:
            ctx->Eax = 0x0;
            ctx->Ebx = 0x1E;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x80000021:
            ctx->Eax = 0x62FCF;
            ctx->Ebx = 0x15C;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x80000022:
            ctx->Eax = 0x7;
            ctx->Ebx = 0x84106;
            ctx->Ecx = 0x3;
            ctx->Edx = 0x0;
            return;
        case 0x80000026:
            ctx->Eax = 0x1;
            ctx->Ebx = 0x2;
            ctx->Ecx = 0x100;
            ctx->Edx = 0x0C;
            return;
        default:
            return;
        };
    };
};

LONG NTAPI nl_veh(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    if (!ExceptionInfo || !ExceptionInfo->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    PEXCEPTION_RECORD rec = ExceptionInfo->ExceptionRecord;
    PCONTEXT ctx = ExceptionInfo->ContextRecord;
    if (!ctx)
        return EXCEPTION_CONTINUE_SEARCH;

    if (!rec->ExceptionAddress)
        return EXCEPTION_CONTINUE_SEARCH;

    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        const DWORD address = reinterpret_cast<DWORD>(
            rec->ExceptionAddress);
        if (is_veh_cpuid_address(address))
        {
            cpuid_emulator(ctx);
            ctx->Eip = address + veh_cpuid_instruction_length(address);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    };

    return EXCEPTION_CONTINUE_SEARCH;
};

void neverlose::set_veh()
{
	PVOID handle = AddVectoredExceptionHandler(0, nl_veh);
	if (!handle)
		panic("Failed to add Vectored Exception Handler!");

	ENTER_LOGGER(logman) << "Added Vectored Exception Handler " << handle << '\n';
};
