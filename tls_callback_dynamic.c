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

static void WINAPI tls_callback_static(HANDLE hDllHandle, DWORD dwReason, LPVOID __UNUSED_PARAM(lpReserved));
static void WINAPI tls_callback_dynamic(HANDLE hDllHandle, DWORD dwReason, LPVOID __UNUSED_PARAM(lpReserved));

_CRTALLOC(".CRT$XLF")
PIMAGE_TLS_CALLBACK tls_callback_function = tls_callback_static;

static void WINAPI tls_callback_static(HANDLE hDllHandle, DWORD dwReason, LPVOID __UNUSED_PARAM(lpReserved))
{
    if (dwReason == DLL_THREAD_ATTACH)
    {
        // This will be loaded in each DLL thread attach
        printf("TLS Callback: Thread Attach Triggered\n");
    }

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        printf("TLS Callback: Process Attach Triggered\n");
        // DEBUG - Help understand how this is being stored in memory.
        printf("TLS Callback Addresses:\n\tFunction Address: %p\n\tCRT Callback Address: %p\n",
               tls_callback_static, &tls_callback_function);

        // The location of the next element in the array of TLS callbacks in memory
        PIMAGE_TLS_CALLBACK *dynamic_callback = (PIMAGE_TLS_CALLBACK *)&tls_callback_function + 1;

        // The default Page Permissions do not necessairly allow us to write to this
        // part of (our) memory. We need to set Write Permissions to the memory range
        // we'll be writing to (here only one callback, thus sizeof(dynamic_callback).
        //
        // Tip: This can be done slightly more stealthy by using the PEB to access
        // kernel32.dll and call this manually.
        DWORD old;
        VirtualProtect(dynamic_callback, sizeof(dynamic_callback), PAGE_EXECUTE_READWRITE, &old);

        // Finally, set the callback in memory, which is next in line to be
        // executed (in our case).
        *dynamic_callback = (PIMAGE_TLS_CALLBACK)tls_callback_dynamic;
    }
}

static void WINAPI tls_callback_dynamic(HANDLE hDllHandle, DWORD dwReason, LPVOID __UNUSED_PARAM(lpReserved))
{
    if (dwReason == DLL_THREAD_ATTACH)
    {
        // This will be loaded in each DLL thread attach
        printf("Dynamic TLS Callback: Thread Attach Triggered\n");
    }

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        printf("Dynamic TLS Callback: Process Attach Triggered\n");

        // DEBUG - Help understand how this is being stored in memory.
        printf("TLS Callback Addresses:\n\tFunction Address: %p\n\tCRT Callback Address: %p\n",
               tls_callback_dynamic, &tls_callback_function + 1);
    }
}

//////////////////////////////////////////////////////////////////////

int main()
{
    return 0;
}
