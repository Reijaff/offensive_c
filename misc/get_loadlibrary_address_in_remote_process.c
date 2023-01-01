
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

DWORD64 get_loadlibrary_address_in_remote_process(DWORD proc_id)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc_id);
	if (NULL == hProcess)
		return 1;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];
			if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				if (!strcmp(szModName, "KERNEL32.DLL"))
				{
					DWORD64 gmh = (DWORD64)GetModuleHandleA("kernel32.dll");
					DWORD64 lla = (DWORD64)GetProcAddress((HMODULE)gmh, "LoadLibraryA");
					DWORD64 offset = lla - gmh;
					printf("local address : %llx\n", gmh);
					printf("remote address : %llx\n", (DWORD64)hMods[i]);

					return (DWORD64)hMods[i] + offset;
				}
			}
		}
	}

	return 0;
}