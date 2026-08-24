#include "neverlose.h"
#include "KUSER_SHARED_DATA_SPOOF.h"
#include "ArenaAllocator.h"
#include "HookFn.h"
void neverlose::spoof_kusd()
{
	auto logger = ENTER_LOGGER(logman);

	PVOID kuser = load_res_to_mem(IDR_KUSER_SHARED, "KUSER_SHARED_DATA");
	logger << "Loaded fake KUSER_SHARED_DATA block at " << kuser << '\n';
	ArenaAllocator<kuser_data_spoof> kuser_arena(g_kuser_spoofs.size());

	if (!kuser_arena.has_scene())
		panic("Failed to allocate KUSER_SHARED_DATA spoof arena!");

	for (auto& [address, reg, nops] : g_kuser_spoofs)
	{
		auto* pspoof_block = kuser_arena.construct(reg, kuser);
		if (!pspoof_block)
			panic("KUSER_SHARED_DATA trampoline arena capacity exceeded!");

		NTSTATUS hkstatus = HookFn((PVOID)address, pspoof_block->data, nops, (PVOID*)&pspoof_block->JumpBackAddr);

		if (NT_SUCCESS(hkstatus))
		{
			// This trampoline needs a fixed destination beyond the copied bytes.
			if (address == 0x431CD6B3)
			{
				BYTE* jmphere = (BYTE*)(pspoof_block->JumpBackAddr + 2);
				PVOID patch_base = jmphere + 1;
				SIZE_T patch_size = sizeof(INT32);
				DWORD old_protection = 0;
				if (!NT_SUCCESS(NtProtectVirtualMemory(
					NtCurrentProcess(),
					&patch_base,
					&patch_size,
					PAGE_EXECUTE_READWRITE,
					&old_protection)))
				{
					panic("Failed to unlock KUSER_SHARED_DATA trampoline!");
				}

				*(INT32*)(jmphere + 1) = 0x42922E5D - (INT32)jmphere - 5;

				PVOID restore_base = jmphere + 1;
				SIZE_T restore_size = sizeof(INT32);
				DWORD ignored = 0;
				NtProtectVirtualMemory(
					NtCurrentProcess(),
					&restore_base,
					&restore_size,
					old_protection,
					&ignored);
				NtFlushInstructionCache(
					NtCurrentProcess(), jmphere + 1, sizeof(INT32));
			}

			logger << "Spoofed KUSER_SHARED_DATA at " << (PVOID)address << '\n';
		}
		else
			logger << "Failed to spoof KUSER_SHARED_DATA at " << (PVOID)address << " with status: " << std::hex << hkstatus << std::dec << '\n';
	};

	if (!kuser_arena.seal())
		logger << "Failed to seal KUSER_SHARED_DATA trampoline arena\n";
};
