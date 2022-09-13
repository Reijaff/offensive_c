#include <windows.h>

typedef int (*Mew)();

int main(void)
{
    HINSTANCE meowDll;
    Mew meowFunc;

    meowDll = LoadLibrary("mylib_export.dll");

    meowFunc = (Mew)GetProcAddress(meowDll, "Mew");

    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)meowFunc, meowDll, 0);
    Sleep(5 * 1000);
    UnhookWindowsHookEx(hook);

    return 0;
}