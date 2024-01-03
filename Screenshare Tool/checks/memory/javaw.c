#include "javaw.h"   

static void AnalyzeStrings(HANDLE hProcess) {
    SIZE_T bytesRead;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = 0;
    unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE);

    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        CloseHandle(hProcess);
        return;
    }

    size_t startIndex = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Type == MEM_PRIVATE) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            address = (unsigned char*)mbi.BaseAddress;

            if (ReadProcessMemory(hProcess, address, buffer, BUFFER_SIZE, &bytesRead)) {
                for (size_t i = 0; i < bytesRead; i++) {
                    if (buffer[i] >= 32 && buffer[i] <= 126) {
                        continue;
                    }

                    if (i - startIndex >= MIN_STRING_LENGTH) {
                        // Check for the specific string "mouse_event"
                        if (strstr((char*)&buffer[startIndex], "Autoclicker.class") != NULL) {
                            wprintf(L"Internal cheat string detected in minecraft process: %lu, ban the user.\n", GetProcessId(hProcess));
                        }
                    }

                    startIndex = i + 1;
                }
            }

            address += bytesRead;
        }
        address += mbi.RegionSize;
    }

    free(buffer);
    CloseHandle(hProcess);
}

void Javaw() {
    setConsoleTextColor(BrightYellow);
    wprintf(L"[Memory Scanner] Running checks to detect internal cheats in Minecraft's memory...\n");
    resetConsoleTextColor();

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error creating process snapshot.\n");
        return;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, "javaw.exe") == 0 || strcmp(pe32.szExeFile, "Minecraft.Windows.exe") == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    // Call the function to analyze strings
                    AnalyzeStrings(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}
