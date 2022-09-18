
#include <windows.h>
#include <stdio.h>

// tls area
//////////////////////////////////////////////////////////////////////

#if defined(_MSC_VER)
#define _CRTALLOC(x) __declspec(allocate(x))
#elif defined(__GNUC__)
#define _CRTALLOC(x) __attribute__((section(x)))
#else
#error Your compiler is not supported.
#endif

static void WINAPI tls_callback(HANDLE hDllHandle, DWORD dwReason, LPVOID __UNUSED_PARAM(lpReserved))
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        printf("attach\n");
        break;
    case DLL_PROCESS_DETACH:
        printf("detach\n");
        break;
    case DLL_THREAD_ATTACH:
        printf("thread attach\n");
        break;
    case DLL_THREAD_DETACH:
        printf("thread detach\n");
        break;
    }
}

// CRT allows the program to register TLS Callbacks.
// The Callbacks to execute are found in a NULL terminated Array.
// A cariable of type PIMAGE_TLS_CALLBACK pointing to the callback must be
// declared in the CRT to register it in this array.
// The compiler can concatenate into one section using the $ symbol.
// The CRT section makes use of a specific naming convention; .CRT$XLx where x
// can be anything between A-Z. A is the beinning, Z is the null terminator.
// All XLx are concatenated into the .CRT section.
// Concatenation is done alphabetically, so the callback in .CRT$XLB will be
// called before .CRT$XLC.
//
// from https://github.com/mirror/mingw-w64/blob/cb37f01f9cb54ccb85ed9c03086e6c4d84b5b431/mingw-w64-crt/crt/tlssup.c

_CRTALLOC(".CRT$XLF")
PIMAGE_TLS_CALLBACK __xl_f = tls_callback;

//////////////////////////////////////////////////////////////////////

int main()
{
    return 0;
}
