#include <windows.h>


int main(int argc, char* argv[]) {
    LoadLibraryA("Z:\\git\\offensive_c\\bin\\dll_mainexec.dll");
    while(1){
        Sleep(10000);
    }
	return 0;
}