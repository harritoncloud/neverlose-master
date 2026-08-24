#include "neverlose.h"

constexpr uintptr_t winver_entry_point = 0x412A0A00;

NTSTATUS __declspec(naked) NTAPI _fictive_(LPVOID lpThreadParameter)
{
	__asm
	{
		push 0
		call RtlExitUserProcess
	};
};

void neverlose::entry()
{
	auto logger = ENTER_LOGGER(logman);

	HANDLE hThread;

#pragma warning(suppress: 28023) // The mapped image entry point has no C declaration to annotate.
	if (!NT_SUCCESS(NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (PUSER_THREAD_START_ROUTINE)winver_entry_point, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, 0, 0x40000, 0x40000, NULL))) panic("Failed to create thread!\n");

	logger << "Created thread.\n";

	THREAD_BASIC_INFORMATION tbi{0};
	if (!NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL))) panic("Failed to get TIB!\n");
	
	logger << "Entry thread: 0x" << tbi.ClientId.UniqueThread << '\n';

	
	if (!NT_SUCCESS(NtResumeThread(hThread, NULL)))
	{
		NtClose(hThread);
		panic("Failed to resume entry thread!\n");
	}

	logger << "Resumed thread.\n";
	tbi = { 0 };

	if (NtWaitForSingleObject(hThread, FALSE, NULL) == STATUS_SUCCESS && NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL)))
		logger << "Entry returned 0x" << std::hex << tbi.ExitStatus << '\n';

	NtClose(hThread);
};
