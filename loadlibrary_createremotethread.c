#include<windows.h>

int main(int argc, char *argv[]) {
	char DllPath[] = "mylib_mainexec.dll";

	// // setup
    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, 0, NORMAL_PRIORITY_CLASS, NULL, NULL, &Startup, &pi);
	WaitForSingleObject(pi.hProcess, 1 * 1000);

    // SuspendThread(pi.hThread);
	// //

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);//(DWORD)pid); 
	LPVOID pDllPath = VirtualAllocEx(handle, 0, sizeof(DllPath), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(handle, pDllPath, (LPVOID)DllPath, sizeof(DllPath), 0);

	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
	HANDLE th = CreateRemoteThread(handle, 0, 0, pLoadLibrary, pDllPath, 0, 0);

	return 0;
}	