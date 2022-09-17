
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

// tlsinit function executes functions allocated in subsections in alphabetical order from xd_a to xd_z
// every function need to be allocated separately with it's own letter
//
// ps = (uintptr_t) &__xd_a;
// ps += sizeof (uintptr_t);
// for ( ; ps != (uintptr_t) &__xd_z; ps += sizeof (uintptr_t))
//
// from https://github.com/mirror/mingw-w64/blob/cb37f01f9cb54ccb85ed9c03086e6c4d84b5b431/mingw-w64-crt/crt/tlssup.c

_CRTALLOC(".CRT$XLF")
PIMAGE_TLS_CALLBACK __xl_f = tls_callback;

//////////////////////////////////////////////////////////////////////

int main()
{
    return 0;
}
