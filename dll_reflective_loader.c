#include <windows.h>
#include <intrin.h>

#define DLL_QUERY_HMODULE 6
extern HINSTANCE hAppInstance;

#define KERNEL32DLL_HASH 0x6A4ABC5B
#define NTDLLDLL_HASH 0x3CFA685D

#define LOADLIBRARYA_HASH 0xEC0E4E8E
#define GETPROCADDRESS_HASH 0x7C0DFCAA
#define VIRTUALALLOC_HASH 0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH 0x534C0AB8

#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

// get rip register
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
__declspec(noinline) ULONG_PTR caller(VOID)
{
    return (ULONG_PTR)WIN_GET_CALLER();
}

#define HASH_KEY 13

// #pragma intrinsic(_rotr)

__forceinline DWORD ror(DWORD d)
{
    return _rotr(d, HASH_KEY);
}

__forceinline DWORD hash(char *c)
{
    register DWORD h = 0;
    do
    {
        h = ror(h);
        h += *c;
    } while (*++c);

    return h;
}

typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI *NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);
typedef BOOL(WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);

typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) )
typedef struct _LDR_DATA_TABLE_ENTRY
{
    // LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK *pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;

typedef struct
{
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;


typedef NTSTATUS(WINAPI *LdrLoadDll_t)(PWCHAR, ULONG, PUNICODE_STR, PHANDLE);

_PPEB GetPeb(VOID)
{
#if defined(_WIN64)
    return (_PPEB)__readgsqword(0x60);
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

INT StringCompareA(LPCSTR String1, LPCSTR String2)
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

BOOL RtlLoadPeHeaders(PIMAGE_DOS_HEADER *Dos, PIMAGE_NT_HEADERS *Nt, PIMAGE_FILE_HEADER *File, PIMAGE_OPTIONAL_HEADER *Optional, PBYTE *ImageBase)
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

    RtlLoadPeHeaders(&Dos, &Nt, &File, &Optional, (PBYTE *)&ModuleBase);

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
        int result = StringCompareA((char *)ModuleBase + FunctionNameAddressArray[middle], lpProcName);
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
    _PPEB Peb = GetPeb();
    PLDR_DATA_TABLE_ENTRY Module = NULL;

    PLIST_ENTRY Head = &Peb->pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY Next = Head->Flink;

    BOOL IsFullPath = wcsrchr(lpModuleName, '\\') ? TRUE : FALSE;

    while (Next != Head)
    {
        Module = (PLDR_DATA_TABLE_ENTRY)((PBYTE)Next - 16);
        if (Module->BaseDllName.pBuffer != NULL)
        {
            if (IsFullPath)
            {
                if (StringCompareInsensitiveW(lpModuleName, Module->FullDllName.pBuffer) == 0)
                {
                    // printf("using module : %ls\n", Module->BaseDllName.Buffer);
                    return (HMODULE)Module->DllBase;
                }
            }
            else
            {
                if (StringCompareInsensitiveW(lpModuleName, Module->BaseDllName.pBuffer) == 0)
                {
                    // printf("using module : %ls\n", Module->BaseDllName.Buffer);
                    return (HMODULE)Module->DllBase;
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

    UNICODE_STR ModuleFileName = {0};
    ModuleFileName.pBuffer = lpModuleName;
    ModuleFileName.Length = StringLengthW(ModuleFileName.pBuffer);
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





DWORD64 ReflectiveLoader()
{
    // STEP 0: calculate our images current base address

    // we will start searching backwards from our callers return address.
    DWORD64 uiLibraryAddress = caller();

    ULONG_PTR uiHeaderValue;
    while (TRUE)
    {
        if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
            {
                uiHeaderValue += uiLibraryAddress;
                // break if we have found a valid MZ/PE header
                if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
                    break;
            }
        }
        uiLibraryAddress--;
    }

    // STEP 1: process the kernels exports for the functions our loader needs...

    // get the Process Enviroment Block
    DWORD64 uiBaseAddress = __readgsqword(0x60);
    uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

    // get the first entry of the InMemoryOrder module list
    DWORD64 uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
    DWORD64 uiValueB;
    DWORD64 uiValueC;
    DWORD64 uiValueD;
    DWORD64 uiValueE;
    USHORT usCounter;
    DWORD64 uiExportDir;
    DWORD64 uiNameArray;
    DWORD64 uiNameOrdinals;
    DWORD64 dwHashValue;
    DWORD64 uiAddressArray;

    LOADLIBRARYA pLoadLibraryA = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    while (uiValueA)
    {
        // get pointer to current modules name (unicode string)
        uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
        // set bCounter to the length for the loop
        usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
        // clear uiValueC which will store the hash of the module name
        uiValueC = 0;

        // compute the hash of the module name...
        do
        {
            uiValueC = ror((DWORD)uiValueC);
            // normalize to uppercase if the madule name is in lowercase
            if (*((BYTE *)uiValueB) >= 'a')
                uiValueC += *((BYTE *)uiValueB) - 0x20;
            else
                uiValueC += *((BYTE *)uiValueB);
            uiValueB++;
        } while (--usCounter);

        // compare the hash with that of kernel32.dll
        if ((DWORD)uiValueC == KERNEL32DLL_HASH)
        {
            // get this modules base address
            uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

            // get the VA of the modules NT Header
            uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

            // uiNameArray = the address of the modules export directory entry
            uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            // get the VA of the export directory
            uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

            // get the VA for the array of name pointers
            uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

            // get the VA for the array of name ordinals
            uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

            usCounter = 3;

            // loop while we still have imports to find
            while (usCounter > 0)
            {
                // compute the hash values for this function name
                dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

                // if we have found a function we want we get its virtual address
                if (dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH)
                {
                    // get the VA for the array of addresses
                    uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

                    // use this functions name ordinal as an index into the array of name pointers
                    uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

                    // store this functions VA
                    if (dwHashValue == LOADLIBRARYA_HASH)
                        pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + DEREF_32(uiAddressArray));
                    else if (dwHashValue == GETPROCADDRESS_HASH)
                        pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + DEREF_32(uiAddressArray));
                    else if (dwHashValue == VIRTUALALLOC_HASH)
                        pVirtualAlloc = (VIRTUALALLOC)(uiBaseAddress + DEREF_32(uiAddressArray));

                    // decrement our counter
                    usCounter--;
                }

                // get the next exported function name
                uiNameArray += sizeof(DWORD);

                // get the next exported function name ordinal
                uiNameOrdinals += sizeof(WORD);
            }
        }
        else if ((DWORD)uiValueC == NTDLLDLL_HASH)
        {
            // get this modules base address
            uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

            // get the VA of the modules NT Header
            uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

            // uiNameArray = the address of the modules export directory entry
            uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            // get the VA of the export directory
            uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

            // get the VA for the array of name pointers
            uiNameArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames);

            // get the VA for the array of name ordinals
            uiNameOrdinals = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals);

            usCounter = 1;

            // loop while we still have imports to find
            while (usCounter > 0)
            {
                // compute the hash values for this function name
                dwHashValue = hash((char *)(uiBaseAddress + DEREF_32(uiNameArray)));

                // if we have found a function we want we get its virtual address
                if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
                {
                    // get the VA for the array of addresses
                    uiAddressArray = (uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

                    // use this functions name ordinal as an index into the array of name pointers
                    uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

                    // store this functions VA
                    if (dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
                        pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(uiBaseAddress + DEREF_32(uiAddressArray));

                    // decrement our counter
                    usCounter--;
                }

                // get the next exported function name
                uiNameArray += sizeof(DWORD);

                // get the next exported function name ordinal
                uiNameOrdinals += sizeof(WORD);
            }
        }

        // we stop searching when we have found everything we need.
        if (pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache)
            break;

        // get the next entry
        uiValueA = DEREF(uiValueA);
    }

    // pVirtualAlloc = (VIRTUALALLOC)RfGetProcAddressA(RfGetModuleHandleW(L"ntdll.dll"), "VirtualAlloc");

    // STEP 2: load our image into a new permanent location in memory...

    // get the VA of the NT Header for the PE to be loaded
    uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

    // allocate all the memory for the DLL to be loaded into. we can load at any address because we will
    // relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
    uiBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // we must now copy over the headers
    uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
    uiValueB = uiLibraryAddress;
    uiValueC = uiBaseAddress;

    while (uiValueA--)
        *(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

    // STEP 3: load in all of our sections...

    // uiValueA = the VA of the first section
    uiValueA = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

    // itterate through all sections, loading them into memory.
    uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
    while (uiValueE--)
    {
        // uiValueB is the VA for this section
        uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

        // uiValueC if the VA for this sections data
        uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

        // copy the section over
        uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

        while (uiValueD--)
            *(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

        // get the VA of the next section
        uiValueA += sizeof(IMAGE_SECTION_HEADER);
    }

    // STEP 4: process our images import table...

    // uiValueB = the address of the import directory
    uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // we assume their is an import table to process
    // uiValueC is the first entry in the import table
    uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

    // itterate through all imports
    while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
    {
        // use LoadLibraryA to load the imported module into memory
        uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

        // uiValueD = VA of the OriginalFirstThunk
        uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

        // uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
        uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

        // itterate through all imported functions, importing by ordinal if no name present
        while (DEREF(uiValueA))
        {
            // sanity check uiValueD as some compilers only import by FirstThunk
            if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // get the VA of the modules NT Header
                uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

                // uiNameArray = the address of the modules export directory entry
                uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                // get the VA of the export directory
                uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

                // get the VA for the array of addresses
                uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

                // use the import ordinal (- export ordinal base) as an index into the array of addresses
                uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

                // patch in the address for this imported function
                DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
            }
            else
            {
                // get the VA of this functions import by name struct
                uiValueB = (uiBaseAddress + DEREF(uiValueA));

                // use GetProcAddress and patch in the address for this imported function
                DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
            }
            // get the next imported function
            uiValueA += sizeof(ULONG_PTR);
            if (uiValueD)
                uiValueD += sizeof(ULONG_PTR);
        }

        // get the next import
        uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    // STEP 5: process all of our images relocations...

    // calculate the base address delta and perform relocations (even if we load at desired image base)
    uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

    // uiValueB = the address of the relocation directory
    uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // check if their are any relocations present
    if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
    {
        // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
        uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

        // and we itterate through all entries...
        while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
        {
            // uiValueA = the VA for this relocation block
            uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

            // uiValueB = number of entries in this relocation block
            uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

            // uiValueD is now the first entry in the current relocation block
            uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

            // we itterate through all the entries in the current block...
            while (uiValueB--)
            {
                // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                // we dont use a switch statement to avoid the compiler building a jump table
                // which would not be very position independent!
                if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
                    *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
                    *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

                // get the next entry in the current relocation block
                uiValueD += sizeof(IMAGE_RELOC);
            }

            // get the next entry in the relocation directory
            uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
        }
    }

    // STEP 6: call our images entry point

    // uiValueA = the VA of our newly loaded DLL/EXE's entry point
    uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

    // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
    pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

    // call our respective entry point, fudging our hInstance value
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
    // if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
    ((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
    // if we are injecting an DLL via a stub we call DllMain with no parameter
    ((DLLMAIN)uiValueA)((HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif

    // STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.

    return 0;
}

HINSTANCE hAppInstance = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    BOOL bReturnValue = TRUE;
    switch (dwReason)
    {
    case DLL_QUERY_HMODULE:
        if (lpReserved != NULL)
            *(HMODULE *)lpReserved = hAppInstance;
        break;
    case DLL_PROCESS_ATTACH:
        hAppInstance = hinstDLL;
        MessageBoxA(NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return bReturnValue;
}
