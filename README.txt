steal other people's code
learn
adapt
repeat

// truncated structure
// get full structure on
// 1. https://www.vergiliusproject.com/
// 2. https://github.com/x64dbg/x64dbg/blob/development/src/dbg/ntdll/ntdll.h
// 3. http://undocumented.ntinternals.net/
// typedef struct _ND_PEB
// {
// BYTE Reserved1[2];
// BYTE BeingDebugged;
// BYTE Reserved2[1];
// PVOID Reserved3[2];
// PND_PEB_LDR_DATA Ldr;
// } ND_PEB, *PND_PEB;