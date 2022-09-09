#include <stdio.h>
#include <windows.h>


int main(int argc, char* argv[]) {
    LoadLibrary("Z:\\git\\offensive_c\\bin\\mylib.dll"); // or "mylib.dll"
    printf("hello");
	return 0;
}