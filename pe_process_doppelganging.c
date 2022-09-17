#include <windows.h>

int main()
{
    // read payload file into heap
	HANDLE hFile = CreateFileW(L"C:\\temp\\payload.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	size_t payload_size = GetFileSize(hFile, 0);
	BYTE* bufferAddress = (BYTE*)VirtualAlloc(0, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD bytesRead = 0;
	ReadFile(hFile, bufferAddress, payload_size, &bytesRead, NULL);

    

    return 0;
}