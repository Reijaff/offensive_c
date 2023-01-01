#include <windows.h>

BOOL WINAPI DllMain(HMODULE hModule, DWORD nReason, LPVOID lpReserved)
{
    switch (nReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(
            NULL,
            "0wn3d!",
            "0wn3d!",
            MB_OK);
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
