#include <windows.h>

typedef int(WINAPI *_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int main(void)
{
	HMODULE hUser32 = LoadLibrary("User32.dll");
	_MessageBoxA MyMessageBoxA = (_MessageBoxA)GetProcAddress(hUser32, "MessageBoxA");
	if (!MyMessageBoxA)
    {
		return -1;
	}

	MyMessageBoxA(NULL, "calling MessageBoxA undirectly", "kek", MB_OK);

	return 0;
}