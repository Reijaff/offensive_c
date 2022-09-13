#include <windows.h>


int main(int argc, char* argv[]) {
    LoadLibraryW(L"mylib_mainexec.dll");
	return 0;
}