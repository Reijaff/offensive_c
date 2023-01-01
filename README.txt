steal other people's code
learn
adapt
repeat

compile with ( https://github.com/mstorsjo/llvm-mingw clang-15) : 
$ x86_64-w64-mingw32-clang -Os ...

TODO:
- https://github.com/janoglezcampos/c_syscalls
- https://github.com/TheKevinWang/UACHooker
- https://github.com/ch3rn0byl/AngryWindows
- https://github.com/SolomonSklash/UnhookingPOC
- https://github.com/trickster0/TartarusGate/
- https://github.com/suspex0/ProxyJect
- https://github.com/TheCruZ/Simple-Manual-Map-Injector -- manualmap + cleanup
- https://github.com/ethicalblue/Self-Erasing-Code-Example/blob/main/self-erase.asm

- offensive_c linux:
    - https://github.com/bediger4000/userlandexec
    - https://github.com/samuraictf/gatekeeper
    - https://github.com/gaffe23/linux-inject

//
compile with "-Wl,--exclude-all-symbols" to disable automatic function export in dll, mingw

pe file analysis + parsing
 - https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 - mingw c autocomplete standart libs in vscode
 - vx-api
    
// truncated structure
// get full structure on
// 1. https://www.vergiliusproject.com/
// 2. https://github.com/x64dbg/x64dbg/blob/development/src/dbg/ntdll/ntdll.h
// 3. http://undocumented.ntinternals.net/
// 4. https://github.com/processhacker/phnt
// typedef struct _ND_PEB
// {
// BYTE Reserved1[2];
// BYTE BeingDebugged;
// BYTE Reserved2[1];
// PVOID Reserved3[2];
// PND_PEB_LDR_DATA Ldr;
// } ND_PEB, *PND_PEB;
