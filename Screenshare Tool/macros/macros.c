#include <Windows.h>
#include <stdio.h>
#include <wchar.h>
#include "macros.h"

void ReplaceUsername(wchar_t* filePath, int maxPathLength) {
    DWORD usernameSize = 0;
    GetUserNameW(NULL, &usernameSize);

    wchar_t* username = NULL;
    if (usernameSize > 0) {
        username = (wchar_t*)malloc(usernameSize * sizeof(wchar_t));
        if (username != NULL) {
            if (GetUserNameW(username, &usernameSize)) {
                wchar_t* placeholder = wcsstr(filePath, L"%username%");
                if (placeholder != NULL) {
                    int placeholderIndex = placeholder - filePath;
                    int usernameLength = wcslen(username);
                    int remainingLength = maxPathLength - placeholderIndex - 1;
                    if (usernameLength <= remainingLength) {
                        wmemmove(filePath + placeholderIndex + usernameLength, filePath + placeholderIndex + 9, remainingLength);
                        wmemcpy(filePath + placeholderIndex, username, usernameLength);
                    }
                }
            }
        }
    }

    free(username);
}

void SearchForDurationMS(const wchar_t* logFilePath) {
    FILE* file = _wfopen(logFilePath, L"r");

    if (file == NULL) {
        return;
    }

    const wchar_t* searchString = L"durationms";
    wchar_t line[512];

    while (fgetws(line, sizeof(line) / sizeof(line[0]), file) != NULL) {
        if (wcsstr(line, searchString) != NULL) {
            wprintf(L"Logitech Macro detected: %s", line);
        }
    }

    fclose(file);
}

void SearchForMacroClientDelete(const wchar_t* logFilePath) {
    FILE* file = _wfopen(logFilePath, L"r");

    if (file == NULL) {
        return;
    }

    const wchar_t* searchString = L"MacroClient:Delete";
    wchar_t line[512];

    while (fgetws(line, sizeof(line) / sizeof(line[0]), file) != NULL) {
        if (wcsstr(line, searchString) != NULL) {
            wprintf(L"Razer Macro detected: %s", line);
        }
    }

    fclose(file);
}

void SearchForTurbo(const wchar_t* logFilePath) {
    FILE* file = _wfopen(logFilePath, L"r");

    if (file == NULL) {
        return;
    }

    const wchar_t* searchString = L"turbo: true";
    wchar_t line[512];

    while (fgetws(line, sizeof(line) / sizeof(line[0]), file) != NULL) {
        if (wcsstr(line, searchString) != NULL) {
            wprintf(L"Razer macro detected: Found 'turbo: true' in the log file.\n");
        }
    }

    fclose(file);
}

// Function to check if a file was modified within the last 60 minutes
bool IsFileRecentlyModified(const wchar_t* filePath) {
    WIN32_FILE_ATTRIBUTE_DATA fileData;
    if (GetFileAttributesEx(filePath, GetFileExInfoStandard, &fileData)) {
        FILETIME lastWriteTime = fileData.ftLastWriteTime;
        SYSTEMTIME currentTime;
        GetSystemTime(&currentTime);
        FILETIME fileTimeUtc;
        SystemTimeToFileTime(&currentTime, &fileTimeUtc);

        ULARGE_INTEGER lastWrite, current;
        lastWrite.LowPart = lastWriteTime.dwLowDateTime;
        lastWrite.HighPart = lastWriteTime.dwHighDateTime;
        current.LowPart = fileTimeUtc.dwLowDateTime;
        current.HighPart = fileTimeUtc.dwHighDateTime;

        // Calculate the time difference in 100 nanoseconds (1 minute = 60,000,000,000 nanoseconds)
        ULARGE_INTEGER diff;
        diff.QuadPart = current.QuadPart - lastWrite.QuadPart;

        if (diff.QuadPart < 60 * 60 * 1e9) {
            return true; // File was modified in the last 60 minutes
        }
    }
    return false; // File not found or not recently modified
}

void CheckFilesInFolder(const wchar_t* folderPath, const wchar_t* extension) {
    wchar_t searchPath[MAX_PATH];
    swprintf_s(searchPath, MAX_PATH, L"%s\\*%s", folderPath, extension);

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, MAX_PATH, L"%s\\%s", folderPath, findFileData.cFileName);

        if (IsFileRecentlyModified(fullPath)) {
            wprintf(L"Warning: Macro file %s was recently modified!\n", fullPath);
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void CheckReadOnlyFilesWithExtension(const wchar_t* folderPath, const wchar_t* extension) {
    wchar_t searchPath[MAX_PATH];
    swprintf_s(searchPath, MAX_PATH, L"%s\\*%s", folderPath, extension);

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, MAX_PATH, L"%s\\%s", folderPath, findFileData.cFileName);

        // Check if the file has the "read-only" attribute set
        if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0) {
            wprintf(L"Warning: Macro file: %s is marked as read-only. This can be used to avoid the macro file being modified when removing macro traces.\n", fullPath);
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}

void CheckRecentFileModifications() {
    DWORD usernameSize = MAX_PATH;
    if (GetUserNameW(username, &usernameSize)) {
        // List of macro file paths to check
        const wchar_t* filePaths[] = {
           L"%appdata%\\Local\\BY-COMBO2",
           L"C:\\Users\\%username%\\AppData\\Local\\Razer\\Synapse3\\Log\\Razer Synapse 3.log",
           L"C:\\Users\\%username%\\AppData\\Local\\LGHUB\\settings.db",
           L"C:\\Users\\%username%\\AppData\\Local\\LGHUB\\setting.db-wal",
           L"C:\\Users\\%username%\\AppData\\Roaming\\steelseries-engine-3-client\\Session Storage\\000003.log",
           L"C:\Program Files\AYAX GamingMouse\\record.ini",
           L"C:\\Program Files\\Gaming MouseV30\\record.ini",
           L"%appdata%\\Local\\BY-COMBO\\curid.dct",
           L"%appdata%\\Local\\BY-COMBO\\pro.dct",
           L"C:\\Program Files (x86)\\Bloody7\\Bloody7\\UserLog\\Mouse\\TLcir_9EFF3FF4\\language\\Settings\\EnvironmentVar.ini",
           L"C:\\ProgramData\\Glorious Core\\userdata\\guru\\data\\MacroDB.db",
           L"C:\\ProgramData\\Glorious Core\\userdata\\guru\\data\\DevicesDB.db",
           L"C:\\Program Files (x86)\\KROM KOLT\\Config\\sequence.dat",
           L"C:\\Program Files (x86)\\SPC Gear",
           L"C:\\Users\\%username%\\AppData\\Roaming\\ROCCAT\\SWARM\\macro\\macro_list.dat",
           L"C:\\Users\\%username%\\AppData\\Roaming\\ROCCAT\\SWARM\\macro\\custom_macro_list.dat",
           L"C:\\Users\\%username%\\AppData\\Roaming\\REDRAGON\\GamingMouse",
           L"C:\\Users\\%username%\\AppData\\Roaming\\REDRAGON\\GamingMouse\\macro.ini",
           L"C:\\Users\\%username%\\AppData\\Roaming\\REDRAGON\\GamingMouse\\config.ini",
           L"C:\\Progam Files (x86)\\AJ390R Gaming Mouse\\data",
           L"C:\\Program Files (x86)\\SPC Gear",
           L"C:\\Program Files (x86)\\Xenon200\\Configs",
           L"C:\\Program Files (x86)\\FANTECH VX7 Gaming Mouse\\config.ini",
           L"C:\\Users\\%username%\\AppData\\Local\\BY-8801-GM917-v108\\curid.dct",
           L"C:\\Users\\%username%\\AppData\\Local\\BY-8801-GM917-v108\\pro.dct",
        };

        int numPaths = sizeof(filePaths) / sizeof(filePaths[0]);

        for (int i = 0; i < numPaths; i++) {
            wchar_t fullPath[MAX_PATH];
            swprintf_s(fullPath, MAX_PATH, L"%s", filePaths[i]);
            ReplaceUsername(fullPath, MAX_PATH, username);

            if (IsFileRecentlyModified(fullPath)) {
                WIN32_FILE_ATTRIBUTE_DATA fileData;
                if (GetFileAttributesEx(fullPath, GetFileExInfoStandard, &fileData)) {
                    FILETIME lastWriteTime = fileData.ftLastWriteTime;
                    SYSTEMTIME st;
                    FileTimeToSystemTime(&lastWriteTime, &st);

                    wprintf(L"Warning: %s was recently modified on %02d/%02d/%d %02d:%02d:%02d!\n", fullPath, st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
                }
            }
        }

        // Modify the path with the ".GMAC" extension and replace %username%
        wchar_t userFolderPath[MAX_PATH];
        swprintf_s(userFolderPath, MAX_PATH, L"C:\\users\\%s\\documents\\ASUS\\ROG\\ROG Armoury\\common\\macro", username);
        ReplaceUsername(userFolderPath, MAX_PATH, username);

        // Append the ".GMAC" extension
        wcscat_s(userFolderPath, MAX_PATH, L".GMAC");

        CheckFilesInFolder(userFolderPath, L".GMAC");

        // Check the modification date of files with certain file extensions in certain macro file paths
        CheckFilesInFolder(L"C:\\Blackweb Gaming AP\\config", L".MA32AIY");
        CheckFilesInFolder(L"C:\\ProgramData\\Alienware\\AlienWare Command Center\\fxmetadata", L".json");
        CheckFilesInFolder(L"C:\\Program Files (x86)\\MotoSpeed Gaming Mouse\\V60\\modules\\setting", L".bin");
        CheckFilesInFolder(L"C:\\Users\\%username%\\Documents\\M711 Gaming Mouse", L"macro.db");

        wchar_t logFilePath[MAX_PATH];
        swprintf_s(logFilePath, MAX_PATH, L"C:\\Users\\%username%\\AppData\\Local\\Razer\\Synapse\\log\\macros\\MacrosRazer3.txt", L"%username%");

        ReplaceUsername(logFilePath, MAX_PATH);

        SearchForMacroClientDelete(logFilePath);

        const wchar_t* logFilePath = L"C:\\ProgramData\\Razer\\Synapse3\\LogSynapseService.log";

        SearchForTurbo(logFilePath);

        wchar_t dbFilePath[MAX_PATH];
        swprintf_s(dbFilePath, MAX_PATH, L"C:\\Users\\%s\\AppData\\Local\\LGHUB\\settings.db", username);

        SearchForDurationMS(dbFilePath);

        CheckReadOnlyFilesWithExtension(L"C:\\Blackweb Gaming AP\\config", L".MA32AIY");
        CheckReadOnlyFilesWithExtension(L"C:\\ProgramData\\Alienware\\AlienWare Command Center\\fxmetadata", L".json");
        CheckReadOnlyFilesWithExtension(L"C:\\Program Files (x86)\\MotoSpeed Gaming Mouse\\V60\\modules\\setting", L".bin");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Local\\LGHUB", L"settings.db");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Local\\LGHUB", L"settings.db-wal");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Local\\Razer\\Synapse3\\Log", L"Razer Synapse 3.log");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Roaming\\steelseries-engine-3-client\\Session Storage", L"000003.log");
        CheckReadOnlyFilesWithExtension(L"C:\Program Files\AYAX GamingMouse", L"record.ini");
        CheckReadOnlyFilesWithExtension(L"C:\\Program Files\\Gaming MouseV30", L"record.ini");
        CheckReadOnlyFilesWithExtension(L"C:\\Program Files (x86)\\Bloody7\\Bloody7\\UserLog\\Mouse\\TLcir_9EFF3FF4\\language\\Settings", L"EnvironmentVar.ini");
        CheckReadOnlyFilesWithExtension(L"C:\\ProgramData\\Glorious Core\\userdata\\guru\\data", L"MacroDB.db");
        CheckReadOnlyFilesWithExtension(L"C:\\ProgramData\\Glorious Core\\userdata\\guru\\data", L"DevicesDB.db");
        CheckReadOnlyFilesWithExtension(L"C:\\Program Files (x86)\\KROM KOLT\\Config", L"sequence.dat");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Roaming\\ROCCAT\\SWARM\\macro", L"macro_list.dat");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Roaming\\ROCCAT\\SWARM\\macro", L"custom_macro_list.dat");
        CheckReadOnlyFilesWithExtension(L"C:\\Program Files (x86)\\FANTECH VX7 Gaming Mouse", L"config.ini");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Local\\BY-8801-GM917-v108", L"curid.dct");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Local\\BY-8801-GM917-v108", L"pro.dct");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\Documents\\M711 Gaming Mouse", L"macro.db");
    }
}