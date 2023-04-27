#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>


int main() {
    const wchar_t startDir[] = L"C:\\Windows\\*";
    WIN32_FIND_DATA FindFileData;
    HANDLE hf = FindFirstFileW(startDir, &FindFileData);

    if (hf == INVALID_HANDLE_VALUE) return;

    FILE* file = fopen("infoDir.txt", "w");

    int i = 0;
    do {
        char temp[256] = { '\0' };
        if (i > 1) {
            sprintf(temp, "%ws", FindFileData.cFileName);
            fputs(temp, file);
            fputc('\n', file);
        }
        i++;
    } while (FindNextFile(hf, &FindFileData));

    FindClose(hf);
    fclose(file);
	return 0;
}