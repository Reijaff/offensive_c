#include <windows.h>
// #include <stdio.h>

//#include "dinvoke.h"
//#include <stdio.h>
//#include <winternl.h>

typedef struct _LSA_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

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

typedef NTSTATUS(WINAPI *LdrLoadDll_t)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

PPEB GetPeb(VOID)
{
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#elif define(_WIN32)
    return (PPEB)__readfsdword(0x30);
#endif
}

wchar_t *wcsrchr(const wchar_t *s, wchar_t c)
{
    const wchar_t *last;

    last = NULL;
    for (;;)
    {
        if (*s == c)
            last = s;
        if (*s == L'\0')
            break;
        s++;
    }

    return ((wchar_t *)last);
}

SIZE_T StringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2)
        ;

    return (String2 - String);
}

int tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c + 'a' - 'A';
    else
        return c;
}

wint_t towlower(wint_t c)
{
    if (c > 0xff)
    {
        return c;
    }
    return (wint_t)tolower((char)c);
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

INT StringCompareInsensitiveW(LPCWSTR s1, LPCWSTR s2)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    unsigned char c1, c2;

    if (p1 == p2)
        return 0;

    do
    {
        c1 = towlower(*p1++);
        c2 = towlower(*p2++);
        if (c1 == '\0')
            break;
    } while (c1 == c2);

    return c1 - c2;
}

// int as_strcmpi(const char *s1, const char *s2)
INT StringCompareInsensitiveA(LPCSTR s1, LPCSTR s2)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    unsigned char c1, c2;

    if (p1 == p2)
        return 0;

    do
    {
        c1 = tolower(*p1++);
        c2 = tolower(*p2++);
        if (c1 == '\0')
            break;
    } while (c1 == c2);

    return c1 - c2;
}

INT string_compare_a(LPCSTR String1, LPCSTR String2)
{
    for (; *String1 == *String2; String1++, String2++)
    {
        if (*String1 == '\0')
            return 0;
    }

    return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

SIZE_T CharStringToWCharString(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed)
{
    INT Length = (INT)MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}

BOOL rtl_load_pe_headers(PIMAGE_DOS_HEADER *Dos, PIMAGE_NT_HEADERS *Nt, PIMAGE_FILE_HEADER *File, PIMAGE_OPTIONAL_HEADER *Optional, PBYTE *ImageBase)
{
    *Dos = (PIMAGE_DOS_HEADER)*ImageBase;
    if ((*Dos)->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    *Nt = (PIMAGE_NT_HEADERS)((PBYTE)*Dos + (*Dos)->e_lfanew);
    if ((*Nt)->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    *File = (PIMAGE_FILE_HEADER)(*ImageBase + (*Dos)->e_lfanew + sizeof(DWORD));
    *Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)*File + sizeof(IMAGE_FILE_HEADER));

    return TRUE;
}

DWORD64 RfGetProcAddressA(DWORD64 ModuleBase, LPCSTR lpProcName)
{
    if (ModuleBase == 0)
    {
        return 0;
    }
    // PBYTE pFunctionName;
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS Nt;
    PIMAGE_FILE_HEADER File;
    PIMAGE_OPTIONAL_HEADER Optional;

    rtl_load_pe_headers(&Dos, &Nt, &File, &Optional, (PBYTE *)&ModuleBase);

    IMAGE_EXPORT_DIRECTORY *ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + Optional->DataDirectory[0].VirtualAddress);

    IMAGE_DOS_HEADER *pDosHdr = (IMAGE_DOS_HEADER *)ModuleBase;
    IMAGE_NT_HEADERS *pNTHdr = (IMAGE_NT_HEADERS *)(ModuleBase + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER *pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY *pDataDir = (IMAGE_DATA_DIRECTORY *)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

    PDWORD FunctionNameAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfFunctions);
    PWORD FunctionOrdinalAddressArray = (PWORD)((LPBYTE)ModuleBase + ExportTable->AddressOfNameOrdinals);

    unsigned long right, left, middle; //, old_middle = 0;
    right = ExportTable->NumberOfNames;
    left = 0;

    DWORD64 pProcAddr = NULL;

    // binary search
    while (right != left)
    {
        middle = left + ((right - left) >> 1);
        int result = string_compare_a((char *)ModuleBase + FunctionNameAddressArray[middle], lpProcName);
        if (!result)
        {
            // printf("found %s\n", lpProcName);
            pProcAddr = (DWORD64)((char *)ModuleBase + FunctionAddressArray[FunctionOrdinalAddressArray[middle]]);
            break;
        }
        else if (result < 0)
            left = middle;
        else
            right = middle;
    }

    // https://devblogs.microsoft.com/oldnewthing/20060719-24/?p=30473
    if ((char *)pProcAddr >= (char *)ExportTable &&
        (char *)pProcAddr < (char *)(ExportTable + pDataDir->Size))
    {
        0;
        // skip for now, todo: find poc
    }

    return pProcAddr;
}

HMODULE RfGetModuleHandleW(LPCWSTR lpModuleName) //, BOOL DoLoad)
{
    PPEB Peb = GetPeb();
    PLDR_MODULE Module = NULL;

    PLIST_ENTRY Head = &Peb->LoaderData->InMemoryOrderModuleList;
    PLIST_ENTRY Next = Head->Flink;

    BOOL IsFullPath = wcsrchr(lpModuleName, '\\') ? TRUE : FALSE;

    while (Next != Head)
    {
        Module = (PLDR_MODULE)((PBYTE)Next - 16);
        if (Module->BaseDllName.Buffer != NULL)
        {
            if (IsFullPath)
            {
                if (StringCompareInsensitiveW(lpModuleName, Module->FullDllName.Buffer) == 0)
                {
                    // printf("using module : %ls\n", Module->BaseDllName.Buffer);
                    return (HMODULE)Module->BaseAddress;
                }
            }
            else
            {
                if (StringCompareInsensitiveW(lpModuleName, Module->BaseDllName.Buffer) == 0)
                {
                    // printf("using module : %ls\n", Module->BaseDllName.Buffer);
                    return (HMODULE)Module->BaseAddress;
                }
            }
        }

        Next = Next->Flink;
    }

    // if (!DoLoad)
    // return NULL;

    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)(ULONG_PTR)RfGetProcAddressA(
        RfGetModuleHandleW(L"ntdll.dll"),
        "LdrLoadDll");

    UNICODE_STRING ModuleFileName = {0};
    ModuleFileName.Buffer = lpModuleName;
    ModuleFileName.Length = StringLengthW(ModuleFileName.Buffer);
    // ModuleFileName.Length *= 2;
    ModuleFileName.MaximumLength = ModuleFileName.Length + 2;

    HANDLE hLibrary = NULL;
    NTSTATUS status = LdrLoadDll(
        NULL,
        0,
        &ModuleFileName,
        &hLibrary);

    // printf("loaded %ls at 0x%p\n", lpModuleName, hLibrary);

    return hLibrary;
}
