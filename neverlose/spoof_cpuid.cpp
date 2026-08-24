#include "neverlose.h"
#include "cpuid_emulator.h"
#include "ArenaAllocator.h"
#include "HookFn.h"
#include <cstring>

namespace
{
	bool patch_veh_cpuid_site(DWORD address)
	{
		const BYTE instruction_length = veh_cpuid_instruction_length(address);
		BYTE expected[3] = { 0x0F, 0xA2, 0x00 };
		const BYTE replacement[3] = { 0xCC, 0x90, 0x90 };

		if (instruction_length == 3)
		{
			expected[0] = veh_cpuid_prefix(address);
			expected[1] = 0x0F;
			expected[2] = 0xA2;
		}

		auto* target = reinterpret_cast<BYTE*>(address);
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(target, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT ||
			(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
		{
			return false;
		}

		const uintptr_t region_begin = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		const uintptr_t region_end = region_begin + mbi.RegionSize;
		if (address < region_begin || address > region_end ||
			static_cast<uintptr_t>(instruction_length) > region_end - address)
		{
			return false;
		}

		if (std::memcmp(target, replacement, instruction_length) == 0)
			return true;

		if (std::memcmp(target, expected, instruction_length) != 0)
			return false;

		PVOID protect_base = target;
		SIZE_T protect_size = instruction_length;
		ULONG old_protect = 0;
		NTSTATUS status = NtProtectVirtualMemory(
			NtCurrentProcess(), &protect_base, &protect_size,
			PAGE_EXECUTE_READWRITE, &old_protect);
		if (!NT_SUCCESS(status))
			return false;

		std::memcpy(target, replacement, instruction_length);
		const bool cache_flushed =
			FlushInstructionCache(GetCurrentProcess(), target, instruction_length) != FALSE;

		ULONG ignored = 0;
		const bool protection_restored = NT_SUCCESS(NtProtectVirtualMemory(
			NtCurrentProcess(), &protect_base, &protect_size, old_protect, &ignored));

		return cache_flushed && protection_restored &&
			std::memcmp(target, replacement, instruction_length) == 0;
	}
}

void neverlose::spoof_cpuid()
{
	auto logger = ENTER_LOGGER(logman);

	PVOID cpuid_emu = load_res_to_mem(IDR_CPUID_EMU, "cpuid emulator");
	logger << "Loaded CPUID emulator at " << cpuid_emu << '\n';

	ArenaAllocator<cpuid_emu_emplacement> cpuid_emu_arena(g_cpuid_emus.size());
	if (!cpuid_emu_arena.has_scene())
		panic("Failed to allocate CPUID trampoline arena!");

	for (auto& [address, nops] : g_cpuid_emus)
	{
		auto* pcpuid_tramp = cpuid_emu_arena.construct(cpuid_emu);
		if (!pcpuid_tramp)
			panic("CPUID trampoline arena capacity exceeded!");

		NTSTATUS hkstatus = HookFn((PVOID)address, pcpuid_tramp->data, nops, (PVOID*)&pcpuid_tramp->JumpBackAddr, 2);
		if (NT_SUCCESS(hkstatus))
			logger << "Emplaced CPUID emulator at " << (PVOID)address << '\n';
		else
			logger << "Failed to emplace CPUID emulator at " << (PVOID)address << " with status: " << std::hex << hkstatus << std::dec << '\n';
	};

	if (!cpuid_emu_arena.seal())
		logger << "Failed to seal CPUID trampoline arena\n";

	for (DWORD bp_addr : g_veh_cpuid_emus)
	{
		if (!patch_veh_cpuid_site(bp_addr))
			logger << "Skipped unsafe CPUID patch at " << reinterpret_cast<PVOID>(bp_addr) << '\n';
	};
};
