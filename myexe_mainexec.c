#include <windows.h>

int WINAPI WinMain(HINSTANCE hThisInstance,
                   HINSTANCE hPrevInstance,
                   LPSTR lpszArgument,
                   int nCmdShow)
{
    MessageBox(
        NULL,
        "owned!",
        "owned!",
        MB_OK);
    return 0;
}
