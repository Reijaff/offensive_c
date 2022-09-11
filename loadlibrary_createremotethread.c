#include<windows.h>

int main(int argc, char *argv[]) {
	char DllPath[] = "mylib_mainexec.dll";

    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, NULL, NORMAL_PRIORITY_CLASS, NULL, NULL, &Startup, &pi);

    SuspendThread(pi.hThread);

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId); 

	LPVOID pDllPath = VirtualAllocEx(handle, 0, sizeof(DllPath), MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(handle, pDllPath, (LPVOID)DllPath, sizeof(DllPath), 0);

	// Create a Remote Thread in the target process which calls LoadLibraryA as our dllpath as an argument -> program loads our dll
	LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
	HANDLE th = CreateRemoteThread(handle, 0, 0, pLoadLibrary, pDllPath, 0, 0);

	WaitForSingleObject(th, INFINITE); 

	VirtualFreeEx(handle, pDllPath, sizeof(DllPath), MEM_RELEASE); // Free the memory allocated for our dll path

	return 0;
}	