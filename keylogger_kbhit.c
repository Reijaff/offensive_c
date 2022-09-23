#include <stdio.h>
#include <conio.h>

int main()
{
    char ch;
    FILE *f;
    f = fopen("keys.txt", "a");
    while (1)
    {
        if (kbhit())
        {
            ch = getch();
            // checking hex value of pressed key and writing into a file
            switch ((int)ch)
            {
            case ' ': // Space key
                fprintf(f, " ");
                break;
            case 0x09: // Tab key.
                fprintf(f, "[TAB]");
                break;
            case 0x0D: // Enter key.
                fprintf(f, "[ENTER]");
                break;
            case 0x1B: // Escape key.
                break;
                fprintf(f, "[ESC]");
            case 0x08: // Backspace key.
                fprintf(f, "[BACKSPACE]");
                break;
            default:
                fputc(ch, f); // other keys will by default print in file
            }
            if ((int)ch == 27)
                break;
        }
    }
    fclose(f);
    return 0;
}