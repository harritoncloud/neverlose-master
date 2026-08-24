#include "neverlose.h"
#include "fix_persist.h"
#include "nadewarn.h"

namespace
{
	const BYTE g_module_anchor = 0;

	bool pin_runtime_module()
	{
		HMODULE pinned_module = nullptr;
		return GetModuleHandleExW(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
				GET_MODULE_HANDLE_EX_FLAG_PIN,
			reinterpret_cast<LPCWSTR>(&g_module_anchor),
			&pinned_module) != FALSE;
	}
}

_Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS NTAPI MainThread(LPVOID lpThreadParameter)
{
	if (!pin_runtime_module())
		return STATUS_UNSUCCESSFUL;

	g_neverlose.map((HMODULE)lpThreadParameter);

	while (!GetModuleHandleW(L"serverbrowser.dll"))
		Sleep(100);

	g_neverlose.fix_dump();
	g_neverlose.set_veh();
	g_neverlose.setup_hooks();
	g_neverlose.spoof();

	g_neverlose.entry();

	return STATUS_SUCCESS;
};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		HANDLE hThread;
		NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), MainThread, hinstDLL, THREAD_CREATE_FLAGS_NONE, 0, 0, 0, NULL);
		if (!NT_SUCCESS(status))
			return FALSE;
		NtClose(hThread);
	}
	else if (fdwReason == DLL_PROCESS_DETACH && lpvReserved == nullptr)
	{
		request_nadewarn_stop();
		request_persist_watchdog_stop();
	}

	return TRUE;
};
