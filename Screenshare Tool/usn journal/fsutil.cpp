#include "..\gui\color.hpp"
#include "fsutil.hpp"

// Function to check if a text file is empty and remove it if so
static bool IsTextFileEmpty(const TCHAR* filename) {
    FILE* file = nullptr;

    if (_tfopen_s(&file, filename, _T("r")) == 0) {
        if (file != nullptr) {
            fseek(file, 0, SEEK_END);
            long size = ftell(file);
            fclose(file);

            if (size == 0) {
                if (_tremove(filename) != 0) {
                    return false;
                }
            }
            return true;
        }
    }

    return false;
}

// Function to build a hash table from a file
static void buildHashTable(FILE* file, FileData*** hashTable, int* tableSize, SYSTEMTIME lastBootTime) {
    char line[MAX_LINE_SIZE];
    *tableSize = 0;
    while (fgets(line, sizeof(line), file) != nullptr) {
        if (strstr(line, "Rename:") != nullptr) {
            // Use a temporary pointer to avoid potential memory leaks
            FileData** tempTable = reinterpret_cast<FileData**>(realloc(*hashTable, (*tableSize + 1) * sizeof(FileData*)));
            if (tempTable == nullptr) {
                perror("Error reallocating memory");
                exit(EXIT_FAILURE);
            }
            *hashTable = tempTable;

            (*hashTable)[*tableSize] = reinterpret_cast<FileData*>(malloc(sizeof(FileData)));
            if ((*hashTable)[*tableSize] == nullptr) {
                perror("Error allocating memory");
                exit(EXIT_FAILURE);
            }

            char* positions[6];
            positions[0] = line;
            for (int i = 1; i < 6; i++) {
                positions[i] = strchr(positions[i - 1] + 1, ',');
                if (positions[i] == nullptr) {
                    break;
                }
            }

            if (positions[5] != nullptr) {
                strncpy_s((*hashTable)[*tableSize]->time, _countof((*hashTable)[*tableSize]->time), positions[5] + 2, positions[5] - positions[4] + 1);
                (*hashTable)[*tableSize]->time[positions[5] - positions[4]] = '\0';

                if (positions[2] != nullptr) {
                    strncpy_s((*hashTable)[*tableSize]->fileName, _countof((*hashTable)[*tableSize]->fileName), (positions[1] != nullptr && positions[2] != nullptr) ? positions[1] + 1 : "", (positions[1] != nullptr && positions[2] != nullptr) ? positions[2] - positions[1] - 1 : 0);
                    (*hashTable)[*tableSize]->fileName[positions[2] - positions[1] - 1] = '\0';

                    (*tableSize)++;
                }
            }
        }
    }
}

// Function to compare hash tables and write results to a file
static void compareHashTables(FileData** hashTable1, int tableSize1, FileData** hashTable2, int tableSize2) {
    Console::SetColor(ConsoleColor::Cyan, ConsoleColor::Black);
    _tprintf(_T("[NTFS Scanner] Detecting replaced files on the entire NTFS drive...\n"));
    Console::ResetColor();
    FILE* outputFile;
    if (fopen_s(&outputFile, "replaced_files.txt", "w") != 0) {
        perror("Error opening replaced_files.txt");
        exit(EXIT_FAILURE);
    }

    FileData* printedLines = nullptr;
    int numPrintedLines = 0;

    for (int i = 0; i < tableSize1; i++) {
        for (int j = 0; j < tableSize2; j++) {
            if (strcmp(hashTable1[i]->fileName, hashTable2[j]->fileName) == 0 &&
                strcmp(hashTable1[i]->time, hashTable2[j]->time) == 0) {

                bool alreadyPrinted = false;
                for (int k = 0; k < numPrintedLines; k++) {
                    if (strcmp(printedLines[k].fileName, hashTable1[i]->fileName) == 0 &&
                        strcmp(printedLines[k].time, hashTable1[i]->time) == 0) {
                        alreadyPrinted = true;
                        break;
                    }
                }

                if (!alreadyPrinted) {
                    // Use a temporary pointer to avoid potential memory leaks
                    FileData* tempLines = reinterpret_cast<FileData*>(realloc(printedLines, (numPrintedLines + 1) * sizeof(FileData)));
                    if (tempLines == nullptr) {
                        perror("Error reallocating memory to detect file replaces.");
                        free(printedLines);
                        exit(EXIT_FAILURE);
                    }
                    printedLines = tempLines;

                    strncpy_s(printedLines[numPrintedLines].time, _countof(printedLines[numPrintedLines].time), hashTable1[i]->time, _TRUNCATE);
                    strncpy_s(printedLines[numPrintedLines].fileName, _countof(printedLines[numPrintedLines].fileName), hashTable1[i]->fileName, _TRUNCATE);
                    numPrintedLines++;
                }
            }
        }
    }

    // Write results to the output file...
    for (int i = 0; i < numPrintedLines; i++) {
        fprintf(outputFile, "%s, %s\n", printedLines[i].fileName, printedLines[i].time);
    }

    fclose(outputFile);

    free(printedLines);
}

// Function to get the last boot time of the system
static void LastBootTime(SYSTEMTIME* lastBootTime) {
    ULONGLONG elapsedTime = GetTickCount64();
    DWORD seconds = (DWORD)(elapsedTime / 1000) % 60;
    DWORD minutes = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000) * 60)) % 60);
    DWORD hours = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000 * 60) * 60)) % 24);

    SYSTEMTIME currentTime;
    GetLocalTime(&currentTime);

    FILETIME ftStartTime;
    SystemTimeToFileTime(&currentTime, &ftStartTime);
    ULARGE_INTEGER startDateTime = *(ULARGE_INTEGER*)&ftStartTime;
    startDateTime.QuadPart -= elapsedTime * 10000;

    FileTimeToSystemTime((FILETIME*)&startDateTime, lastBootTime);
}

// Function to process the log file comparison
static void processLogFileComparison() {
    SYSTEMTIME lastBootTime;
    LastBootTime(&lastBootTime);

    FILE* file1, * file2;
    if (fopen_s(&file1, "old_renamed_files.txt", "r") != 0 || fopen_s(&file2, "new_renamed_files.txt", "r") != 0) {
        exit(EXIT_FAILURE);
    }

    FileData** hashTable1 = nullptr;
    FileData** hashTable2 = nullptr;
    int tableSize1, tableSize2;

    buildHashTable(file1, &hashTable1, &tableSize1, lastBootTime);
    buildHashTable(file2, &hashTable2, &tableSize2, lastBootTime);

    compareHashTables(hashTable1, tableSize1, hashTable2, tableSize2);

    // Free allocated memory...
    for (int i = 0; i < tableSize1; i++) {
        free(hashTable1[i]);
    }
    free(hashTable1);

    for (int i = 0; i < tableSize2; i++) {
        free(hashTable2[i]);
    }
    free(hashTable2);

    fclose(file1);
    fclose(file2);

    // Get the current working directory
    std::filesystem::path currentPath = std::filesystem::current_path();
    std::cout << "Current working directory: " << currentPath << std::endl;

    // Construct full file paths
    std::filesystem::path oldFilePath = currentPath / "old_renamed_files.txt";
    std::filesystem::path newFilePath = currentPath / "new_renamed_files.txt";

    // Attempt to delete renamed files
    std::filesystem::remove(oldFilePath);
    std::filesystem::remove(newFilePath);
}

// Function to convert a wide-character string to a multibyte string
static int ConvertWideCharToMultiByte(const wchar_t* wideStr, char* multiByteStr, size_t size) {
    return WideCharToMultiByte(CP_ACP, 0, wideStr, -1, multiByteStr, (int)size, nullptr, nullptr);
}

// Function to run journal query for a specific drive
static void RunCommand(TCHAR driveLetter) {
    TCHAR command[MAX_PATH] = { 0 };
    char charCommand[MAX_PATH] = { 0 };

    Console::SetColor(ConsoleColor::Cyan, ConsoleColor::Black);
    _tprintf(_T("[NTFS Scanner] Running journal query for drive %c.\n"), driveLetter);
    _tprintf(_T("[NTFS Scanner] Detecting file rename modifications in the entire NTFS drive...\n"));

    int result = _stprintf_s(command, _T("fsutil usn readjournal %c: csv | findstr /i /c:0x00001000 >> .\\old_renamed_files.txt"), driveLetter);
    system(command);

    _stprintf_s(command, _T("fsutil usn readjournal %c: csv | findstr /i /c:0x00002000 >> .\\new_renamed_files.txt"), driveLetter);
    system(command);

    _tprintf(_T("[NTFS Scanner] Detecting every file modification with any special character...\n"));
    _stprintf_s(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\"?\" >> .\\special_characters.txt"), driveLetter);
    system(command);

    _tprintf(_T("[NTFS Scanner] Detecting glorious macro traces on the entire NTFS drive...\n"));
    _stprintf_s(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".mcf\" >> .\\glorious.txt"), driveLetter);
    system(command);

    _tprintf(_T("[NTFS Scanner] Detecting Logitech macro traces on the entire NTFS drive...\n"));
    _stprintf_s(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\"settings\\.db\" >> .\\logitech.txt"), driveLetter);
    system(command);

    _tprintf(_T("[NTFS Scanner] Detecting Bloody macro traces on the entire NTFS drive...\n"));
    _stprintf_s(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".amc2\" >> .\\bloody.txt"), driveLetter);
    system(command);

    _tprintf(_T("[NTFS Scanner] Detecting Corsair macro traces on the entire NTFS drive...\n"));
    _stprintf_s(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".cuecfg\" >> .\\corsair.txt"), driveLetter);
    system(command);

    Console::ResetColor();

    IsTextFileEmpty(_T("old_renamed_files.txt"));
    IsTextFileEmpty(_T("new_renamed_files.txt"));
    IsTextFileEmpty(_T("special_characters.txt"));
    IsTextFileEmpty(_T("glorious.txt"));
    IsTextFileEmpty(_T("logitech.txt"));
    IsTextFileEmpty(_T("bloody.txt"));
    IsTextFileEmpty(_T("corsair.txt"));
}

void USNJournal() {
    TCHAR szLogicalDrives[MAX_PATH];
    if (GetLogicalDriveStrings(MAX_PATH, szLogicalDrives) == 0) {
        return;
    }

    bool allDrivesProcessed = false;

    for (TCHAR* pDrive = szLogicalDrives; *pDrive != '\0'; pDrive += _tcslen(pDrive) + 1) {
        if (_tcslen(pDrive) == 3 && pDrive[1] == ':' && pDrive[2] == '\\') {
            TCHAR szFileSystem[MAX_PATH];
            if (GetVolumeInformation(pDrive, nullptr, 0, nullptr, nullptr, nullptr, szFileSystem, MAX_PATH)) {
                if (_tcsicmp(szFileSystem, _T("NTFS")) == 0) {
                    RunCommand(pDrive[0]);
                }
                else {
                    allDrivesProcessed = true;
                }
            }
        }
    }

    if (allDrivesProcessed) {
        processLogFileComparison();
    }

    Console::SetColor(ConsoleColor::Cyan, ConsoleColor::Black);
    _tprintf(_T("[NTFS Scanner] File modifications will be output to your current working directory.\n"));
    _tprintf(_T("[NTFS Scanner] You can see your current working directory path in the line where you specified the file path in the command prompt.\n"));
    _tprintf(_T("[NTFS Scanner] If you opened this exe without opening first a command prompt, then the .txt files are in the same path as the Screenshare Tool.\n"));
    _tprintf(_T("[NTFS Scanner] Order the folder by \"Date modified\" and open the most recent \".txt\" files to check all important modifications.\n"));
    Console::ResetColor();

}