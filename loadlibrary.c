#include <windows.h>


int main(int argc, char* argv[]) {
    LoadLibraryW(L"dll_morph_module.dll");
    while(1){
        Sleep(10000);
    }
	return 0;
}