#include "fsutil.h"

// Function to check if the usnjournal parser exported information to the output file. If not, we remove the file
bool IsTextFileEmpty(const TCHAR* filename) {
    FILE* file = _tfopen(filename, _T("r"));

    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fclose(file);

        if (size == 0) {
            // File is empty, remove it
            if (remove(filename) != 0) {
                // Unable to remove the file
                return false;
            }
        }
        return true;
    }

    // File not found or cannot be opened
    return false;
}

void RunCommand(TCHAR driveLetter) {
    TCHAR command[MAX_PATH] = { 0 };

    _tprintf(_T("Running journal query for drive %c...\n"), driveLetter);
    _tprintf(_T("Detecting file rename modifications on all files.\n"));

    // Run fsutil usn readjournal and filter for old renamed files
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /c:0x00001000 >> old_renamed_files.txt"), driveLetter);
    system(command);

    // Run fsutil usn readjournal and filter for new renamed files
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /c:0x00002000 >> new_renamed_files.txt"), driveLetter);
    system(command);

    _tprintf(_T("Detecting files with special characters in all the drive.\n"));
    // Run fsutil usn readjournal and filter for special characters
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\"?\" >> special_characters.txt"), driveLetter);
    system(command);

    _tprintf(_T("Running checks for Glorious macros modifications.\n"));
    // Run fsutil usn readjournal and filter for glorious macros
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".mcf\" >> glorious.txt"), driveLetter);
    system(command);

    _tprintf(_T("Running checks for Logitech macros modifications.\n"));
    // Run fsutil usn readjournal and filter for logitech macros
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\"settings\\.db\" >> logitech.txt"), driveLetter);
    system(command);

    _tprintf(_T("Running checks for Bloody macros modifications.\n"));
    // Run fsutil usn readjournal and filter for bloody macros
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".amc2\" >> bloody.txt"), driveLetter);
    system(command);
    
     _tprintf(_T("Running checks for Corsair macros modifications.\n"));
    // Run fsutil usn readjournal and filter for corsair macros
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".cuecfg\" >> corsair.txt"), driveLetter);
    system(command);

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

    bool allDrivesProcessed = false;  // Flag to track if all NTFS drives have been processed

    for (TCHAR* pDrive = szLogicalDrives; *pDrive != '\0'; pDrive += _tcslen(pDrive) + 1) {
        if (_tcslen(pDrive) == 3 && pDrive[1] == ':' && pDrive[2] == '\\') {
            // Check if it's an NTFS drive
            TCHAR szFileSystem[MAX_PATH];
            if (GetVolumeInformation(pDrive, NULL, 0, NULL, NULL, NULL, szFileSystem, MAX_PATH)) {
                if (_tcsicmp(szFileSystem, _T("NTFS")) == 0) {
                    // Run the command for the current drive letter
                    RunCommand(pDrive[0]);
                } else {
                    allDrivesProcessed = true;  
                }
            }
        }
    }

    if (allDrivesProcessed) {
        // Call processLogFileComparison only if all NTFS drives have been processed
        processLogFileComparison();
    }
}

// Function to build a hash table from a file based on time
void buildHashTable(FILE *file, FileData ***hashTable, int *tableSize, SYSTEMTIME lastBootTime) {
    char line[MAX_LINE_SIZE];
    *tableSize = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "Rename:") != NULL) {
            *hashTable = realloc(*hashTable, (*tableSize + 1) * sizeof(FileData*));
            (*hashTable)[*tableSize] = malloc(sizeof(FileData));

            // Find the positions of commas in the line
            char *positions[6];
            positions[0] = line;
            for (int i = 1; i < 6; i++) {
                positions[i] = strchr(positions[i - 1] + 1, ',');
                if (positions[i] == NULL) {
                    break;
                }
            }

            if (positions[5] != NULL) {
                strncpy((*hashTable)[*tableSize]->time, positions[5] + 2, positions[5] - positions[4] + 1);
                (*hashTable)[*tableSize]->time[positions[5] - positions[4]] = '\0';

                if (positions[2] != NULL) {
                    strncpy((*hashTable)[*tableSize]->fileName, positions[1] + 1, positions[2] - positions[1] - 1);
                    (*hashTable)[*tableSize]->fileName[positions[2] - positions[1] - 1] = '\0';

                    (*tableSize)++;
                }
            }
        }
    }
}

// Function to compare hash tables and output matches to replaced_files.txt
void compareHashTables(FileData **hashTable1, int tableSize1, FileData **hashTable2, int tableSize2) {
    FILE *outputFile = fopen("replaced_files.txt", "w");

    if (outputFile == NULL) {
        perror("Error opening replaced_files.txt");
        exit(EXIT_FAILURE);
    }

    // Array to store already printed lines
    FileData *printedLines = NULL;
    int numPrintedLines = 0;

    for (int i = 0; i < tableSize1; i++) {
        for (int j = 0; j < tableSize2; j++) {
            if (strcmp(hashTable1[i]->fileName, hashTable2[j]->fileName) == 0 &&
                strcmp(hashTable1[i]->time, hashTable2[j]->time) == 0) {
                
                // Check if the line is already printed
                bool alreadyPrinted = false;
                for (int k = 0; k < numPrintedLines; k++) {
                    if (strcmp(printedLines[k].fileName, hashTable1[i]->fileName) == 0 &&
                        strcmp(printedLines[k].time, hashTable1[i]->time) == 0) {
                        alreadyPrinted = true;
                        break;
                    }
                }

                // If not already printed, output to replaced_files.txt
                if (!alreadyPrinted) {
                    fprintf(outputFile, "File replaced at: %s, FileName: %s\n", hashTable1[i]->time, hashTable1[i]->fileName);

                    // Resize the array and add the printed line
                    printedLines = realloc(printedLines, (numPrintedLines + 1) * sizeof(FileData));
                    if (printedLines == NULL) {
                        perror("Error reallocating memory to detect file replaces.");
                        exit(EXIT_FAILURE);
                    }

                    strcpy(printedLines[numPrintedLines].time, hashTable1[i]->time);
                    strcpy(printedLines[numPrintedLines].fileName, hashTable1[i]->fileName);
                    numPrintedLines++;
                }
            }
        }
    }

    free(printedLines);

    fclose(outputFile);
}

void LastBootTime() {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

    // Calculate elapsed time in seconds, minutes, and hours
    DWORD seconds = (DWORD)(elapsedTime / 1000) % 60;
    DWORD minutes = (DWORD)((elapsedTime / (1000 * 60)) % 60);
    DWORD hours = (DWORD)((elapsedTime / (1000 * 60 * 60)) % 24);

    // Get the current local time
    SYSTEMTIME currentTime;
    GetLocalTime(&currentTime);

    // Calculate the time when the computer started
    FILETIME ftStartTime;
    SystemTimeToFileTime(&currentTime, &ftStartTime);
    ULARGE_INTEGER startDateTime = *(ULARGE_INTEGER*)&ftStartTime;
    startDateTime.QuadPart -= elapsedTime * 10000; // Convert elapsed time to 100-nanosecond intervals

    // Convert the calculated start time back to SYSTEMTIME
    SYSTEMTIME startTime;
    FileTimeToSystemTime((FILETIME*)&startDateTime, &startTime);

    // Print the results
    printf("Computer started on: %02d/%02d/%04d %02d:%02d:%02d\n",
           startTime.wMonth, startTime.wDay, startTime.wYear,
           startTime.wHour, startTime.wMinute, startTime.wSecond);
}

// Function to process log file comparison
void processLogFileComparison() {
    SYSTEMTIME lastBootTime;
    LastBootTime(&lastBootTime);

    // Open the log files for reading
    FILE* file1 = fopen("old_renamed_files.txt", "r");
    FILE* file2 = fopen("new_renamed_files.txt", "r");

    // Check if files were successfully opened
    if (file1 == NULL || file2 == NULL) {
        perror("Error opening files");
        exit(EXIT_FAILURE);
    }

    // Initialize hash tables and sizes
    FileData** hashTable1 = NULL;
    FileData** hashTable2 = NULL;
    int tableSize1, tableSize2;

    // Build hash tables from log files
    buildHashTable(file1, &hashTable1, &tableSize1, lastBootTime);
    buildHashTable(file2, &hashTable2, &tableSize2, lastBootTime);

    // Compare hash tables and print differences
    compareHashTables(hashTable1, tableSize1, hashTable2, tableSize2);

    // Free memory for hash tables
    for (int i = 0; i < tableSize1; i++) {
        free(hashTable1[i]);
    }
    free(hashTable1);

    for (int i = 0; i < tableSize2; i++) {
        free(hashTable2[i]);
    }
    free(hashTable2);

    // Close log files
    fclose(file1);
    fclose(file2);

    // Delete log files
    if (remove("old_renamed_files.txt") != 0) {
        perror("Error deleting old_renamed_files.txt");
    }

    if (remove("new_renamed_files.txt") != 0) {
        perror("Error deleting new_renamed_files.txt");
    }
}