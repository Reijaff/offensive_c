#include<windows.h>

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FilePositionInformation = 14,
	FileEndOfFileInformation = 20,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;							// Created             
	LARGE_INTEGER LastAccessTime;                       // Accessed    
	LARGE_INTEGER LastWriteTime;                        // Modifed
	LARGE_INTEGER ChangeTime;                           // Entry Modified
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;



typedef NTSTATUS(WINAPI *pNtSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(WINAPI *pNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);


int main(){

    char * srcFileName = "C:\\Windows\\System32\\at.exe";
    char * dstFileName = "C:\\tmp\\text.txt";

    FILE_BASIC_INFORMATION dst_fbi, src_fbi;
    IO_STATUS_BLOCK ioStat;

	HMODULE ntdll = GetModuleHandle(TEXT("ntdll.dll"));
    pNtQueryInformationFile NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(ntdll, "NtQueryInformationFile");
    pNtSetInformationFile NtSetInformationFile = (pNtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");

    HANDLE srcFile = CreateFile(srcFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE dstFile = CreateFile(dstFileName, GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);

    NtQueryInformationFile(srcFile, &ioStat, &src_fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
    NtQueryInformationFile(dstFile, &ioStat, &dst_fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);

    dst_fbi.LastWriteTime = src_fbi.LastWriteTime;
    dst_fbi.LastAccessTime = src_fbi.LastAccessTime;
    dst_fbi.ChangeTime = src_fbi.ChangeTime;
    dst_fbi.CreationTime = src_fbi.CreationTime;

    NtSetInformationFile(dstFile, &ioStat, &dst_fbi, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);

    CloseHandle(srcFile);
    CloseHandle(dstFile);

    return 0;
}
