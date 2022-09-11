#include <stdio.h>
#include <windows.h>


int main(int argc, char* argv[]) {
    LoadLibraryW(L"mylib_mainexec.dll");
    printf("hello");
	return 0;
}