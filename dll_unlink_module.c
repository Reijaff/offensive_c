#include <windows.h>
#include<stdio.h>

typedef struct _LSA_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, *PCURDIR;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LDR_MODULE
{
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBase;
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID *KernelCallbackTable;
    PVOID EventLogSection;
    PVOID EventLog;
    PVOID FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[0x2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    BYTE Spare2[0x4];
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID **ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    ULONG OSBuildNumber;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG GdiHandleBuffer[0x22];
    ULONG PostProcessInitRoutine;
    ULONG TlsExpansionBitmap;
    BYTE TlsExpansionBitmapBits[0x80];
    ULONG SessionId;
} PEB, *PPEB;

PPEB GetPeb(VOID)
{
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#elif define(_WIN32)
    return (PPEB)__readfsdword(0x30);
#endif
}

INT StringCompareW(LPCWSTR String1, LPCWSTR String2)
{
    for (; *String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

typedef int(WINAPI *_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString);

void UnlinkModule()
{

    LPCWSTR lpModuleName = L"dll_morph_module.dll";
    PPEB Peb = GetPeb();

    // unlink the object from the lists in InLoadOrderLinks
    PLDR_MODULE Module = NULL;

    PLIST_ENTRY Head = &Peb->LoaderData->InLoadOrderModuleList;
    PLIST_ENTRY Next = Head->Flink;
    Module = (PLDR_MODULE)((PBYTE)Next - 16);

    while (Next != Head)
    {
        Module = (PLDR_MODULE)((PBYTE)Next - 16);
        if (Module->BaseDllName.Buffer != NULL)
        {
            if (StringCompareW(lpModuleName, Module->BaseDllName.Buffer) == 0)
            {
                Module->HashTableEntry.Blink->Flink = Module->HashTableEntry.Flink;
                Module->HashTableEntry.Flink->Blink = Module->HashTableEntry.Blink;
                Module->InLoadOrderModuleList.Blink->Flink = Module->InLoadOrderModuleList.Flink;
                Module->InLoadOrderModuleList.Flink->Blink = Module->InLoadOrderModuleList.Blink;
                break;
            }
        }

        Next = Next->Flink;
    }

    // unlink the object from the lists in InInitializationOrderLinks
    Module = NULL;

    Head = &Peb->LoaderData->InInitializationOrderModuleList;
    Next = Head->Flink;
    Module = (PLDR_MODULE)((PBYTE)Next - 16);

    while (Next != Head)
    {
        Module = (PLDR_MODULE)((PBYTE)Next - 16);
        if (Module->BaseDllName.Buffer != NULL)
        {
            if (StringCompareW(lpModuleName, Module->BaseDllName.Buffer) == 0)
            {
                Module->HashTableEntry.Blink->Flink = Module->HashTableEntry.Flink;
                Module->HashTableEntry.Flink->Blink = Module->HashTableEntry.Blink;
                Module->InLoadOrderModuleList.Blink->Flink = Module->InLoadOrderModuleList.Flink;
                Module->InLoadOrderModuleList.Flink->Blink = Module->InLoadOrderModuleList.Blink;
                break;
            }
        }

        Next = Next->Flink;
    }

    // TODO: fix crash
    // unlink the object from the lists in InMemoryOrderModuleList
    // Module = NULL;

    // Head = &Peb->LoaderData->InMemoryOrderModuleList;
    // Next = Head->Flink;
    // Module = (PLDR_MODULE)((PBYTE)Next - 16);

    // while (Next != Head)
    // {
        // Module = (PLDR_MODULE)((PBYTE)Next - 16);
        // if (Module->BaseDllName.Buffer != NULL)
        // {
            // if (StringCompareW(lpModuleName, Module->BaseDllName.Buffer) == 0)
            // {
                // Module->HashTableEntry.Blink->Flink = Module->HashTableEntry.Flink;
                // Module->HashTableEntry.Flink->Blink = Module->HashTableEntry.Blink;
                // Module->InLoadOrderModuleList.Blink->Flink = Module->InLoadOrderModuleList.Flink;
                // Module->InLoadOrderModuleList.Flink->Blink = Module->InLoadOrderModuleList.Blink;
                // break;
            // }
        // }

        // Next = Next->Flink;
    // }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        UnlinkModule();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return 0;
}