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
            FileData** tempTable = reinterpret_cast<FileData**>(realloc(*hashTable, (static_cast<unsigned long long>(*tableSize) + 1) * sizeof(FileData*)));
            if (tempTable == nullptr) {
                exit(EXIT_FAILURE);
            }
            *hashTable = tempTable;

            (*hashTable)[*tableSize] = reinterpret_cast<FileData*>(malloc(sizeof(FileData)));
            if ((*hashTable)[*tableSize] == nullptr) {
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
    setConsoleTextColor(Cyan);
    _tprintf(_T("[NTFS Scanner] Detecting replaced files on the entire NTFS drive...\n"));
    resetConsoleTextColor();

    FILE* outputFile;
    if (fopen_s(&outputFile, "replaced_files.txt", "w") != 0) {
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

/**
 * Gets the last boot time of the system.
 * 
 * This function calculates the last boot time of the system based on the elapsed time since the system was started.
 * It uses the GetTickCount64 function to obtain the system uptime, then converts the elapsed time to hours, minutes, and seconds.
 * The current local time is retrieved using GetLocalTime, and the last boot time is calculated by subtracting the elapsed time.
 * The result is stored in the provided SYSTEMTIME structure.
 * 
 */
static void LastBootTime(SYSTEMTIME* lastBootTime) {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

    // Calculate elapsed time in seconds, minutes, and hours
    DWORD seconds = (DWORD)(elapsedTime / 1000) % 60;
    DWORD minutes = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000) * 60)) % 60);
    DWORD hours = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000 * 60) * 60)) % 24);

    // Get the current local time
    SYSTEMTIME currentTime;
    GetLocalTime(&currentTime);

    // Calculate the time when the computer started
    FILETIME ftStartTime;
    SystemTimeToFileTime(&currentTime, &ftStartTime);
    ULARGE_INTEGER startDateTime = *(ULARGE_INTEGER*)&ftStartTime;
    startDateTime.QuadPart -= elapsedTime * 10000; // Convert elapsed time to 100-nanosecond intervals

    // Convert the calculated start time back to SYSTEMTIME
    FileTimeToSystemTime((FILETIME*)&startDateTime, lastBootTime);
}

// Function to process the log file comparison
/**
 * Processes the comparison of two log files containing renamed files information.
 *
 * This function reads two log files ("old_renamed_files.txt" and "new_renamed_files.txt"),
 * builds hash tables for each file, and then compares the hash tables to identify renamed files.
 * The hash tables are built based on file data and the last boot time of the system.
 *
 * The file format is assumed to contain information about renamed files.
 * Each line in the file is expected to have relevant data about a file, separated by appropriate delimiters.
 *
 */
static void processLogFileComparison() {
    // Get the last boot time of the system
    SYSTEMTIME lastBootTime;
    LastBootTime(&lastBootTime);

    // Open the log files for reading
    FILE* file1, * file2;
    if (fopen_s(&file1, "old_renamed_files.txt", "r") != 0 ||
        fopen_s(&file2, "new_renamed_files.txt", "r") != 0) {
        exit(EXIT_FAILURE);
    }

    // Initialize variables for hash tables and their sizes
    FileData** hashTable1 = nullptr;
    FileData** hashTable2 = nullptr;
    int tableSize1, tableSize2;

    // Build hash tables for each log file
    buildHashTable(file1, &hashTable1, &tableSize1, lastBootTime);
    buildHashTable(file2, &hashTable2, &tableSize2, lastBootTime);

    // Compare the hash tables to identify renamed files
    compareHashTables(hashTable1, tableSize1, hashTable2, tableSize2);

    // Free allocated memory for hash tables
    for (int i = 0; i < tableSize1; i++) {
        free(hashTable1[i]);
    }
    free(hashTable1);

    for (int i = 0; i < tableSize2; i++) {
        free(hashTable2[i]);
    }
    free(hashTable2);

    // Close the log files
    fclose(file1);
    fclose(file2);

    // Attempt to delete unnecesary log files
    std::filesystem::remove(L"new_renamed_files.txt");
    std::filesystem::remove(L"old_renamed_files.txt");
}

// Function to convert a wide-character string to a multibyte string
static int ConvertWideCharToMultiByte(const wchar_t* wideStr, char* multiByteStr, size_t size) {
    return WideCharToMultiByte(CP_ACP, 0, wideStr, -1, multiByteStr, (int)size, nullptr, nullptr);
}

// Function to run journal query for a specific drive (to detect file modifications)
static void RunCommand(TCHAR driveLetter) {
    TCHAR command[MAX_PATH] = { 0 };
    char charCommand[MAX_PATH] = { 0 };

    setConsoleTextColor(Cyan);
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

    resetConsoleTextColor();

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

    // Makes the USNJournal scanner only scan NTFS drives (only drives with journal)
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

    resetConsoleTextColor();
    // Get the current working directory
    std::filesystem::path currentPath = std::filesystem::current_path();

    // Print the current working directory
    std::cout << "File modifications were exported to: " << currentPath << std::endl;

    _tprintf(_T("Order the folder by \"Date modified\" and open the most recent \".txt\" files to check all important modifications.\n"));
    _tprintf(_T("You should ban the user if you find a modification made just before the Screenshare.\n"));
}