#include "macros.h"

wchar_t username[MAX_PATH];

// Function to log errors
static void LogError(const wchar_t* errorMessage) {
    wprintf(L"Error ocurred while checking macro files: %s\n", errorMessage);
}

// Function to replace the "%username%" placeholder in a file path with the actual username
static void ReplaceUsername(wchar_t* filePath, int maxPathLength, const wchar_t* replacementUsername) {
    size_t usernameSize = wcslen(replacementUsername);

    const wchar_t* placeholder = L"%username%";
    wchar_t* position = wcsstr(filePath, placeholder);

    while (position != NULL) {
        size_t placeholderIndex = position - filePath;
        size_t remainingLength = maxPathLength - placeholderIndex - wcslen(placeholder);

        if (usernameSize <= remainingLength) {
            wmemmove(filePath + placeholderIndex + usernameSize, position + wcslen(placeholder), remainingLength);
            wmemcpy(filePath + placeholderIndex, replacementUsername, usernameSize);
        }

        position = wcsstr(filePath + placeholderIndex + usernameSize, placeholder);
    }
}

// I make separate functions so that the intentionality its more clear

// Function to search for "durationMs" in the Logitech macro file
static void SearchForDurationMS(const wchar_t* logFilePath) {
    FILE* file = NULL;
    errno_t err;

    // Try to open the file
    if ((err = _wfopen_s(&file, logFilePath, L"r")) == 0) {
        const wchar_t* searchString = L"\"durationMs\":";
        wchar_t line[1024];

        // Check if the file pointer is not NULL before entering the loop
        while (file != NULL && fgetws(line, sizeof(line) / sizeof(line[0]), file) != NULL) {
            // Use case-insensitive search
            if (_wcsicmp(line, searchString) != 0) {
                wprintf(L"[!] Logitech Macro detected. Ban the player.");
            }
        }

        // Close the macro file
        if (file != NULL) { // this is just to avoid compiler warnings
            fclose(file);
        }
    }
    else {
        if (err == EACCES) {
            wprintf(L"[#] Permission denied when accessing the macro file: %s when checking for macro traces. Manually check if this file contains the string 'durationMs.'\n", logFilePath);
        }
    }
}


// Function to search for "MacroClient:Delete" in the Razer macro file (Deleted macro trace)
static void SearchForMacroClientDelete(const wchar_t* logFilePath) {
    FILE* file = NULL;
    if (_wfopen_s(&file, logFilePath, L"r, ccs=UTF-8") == 0) {
        const wchar_t* searchString = L"MacroClient:Delete";
        wchar_t line[512];

        while (file != NULL && fgetws(line, sizeof(line) / sizeof(line[0]), file) != NULL) {
            if (wcsstr(line, searchString) != NULL) {
                wprintf(L"[!] Razer Macro detected and deleted: %ls. Ban the player.", line);
            }
        }

        if (file != NULL) {
            fclose(file);
        }
    }
    else {
        return;
    }
}

// Function to search for "turbo: true" in the Razer macro file (Razer Turbo Method)
static void SearchForTurbo(const wchar_t* logFilePath) {
    FILE* file = NULL;
    errno_t err = _wfopen_s(&file, logFilePath, L"r, ccs=UTF-8");
    if (err == 0 && file != NULL) {
        const wchar_t* searchString = L"turbo: true";
        wchar_t line[512];

        while (fgetws(line, sizeof(line) / sizeof(line[0]), file) != NULL) {
            if (wcsstr(line, searchString) != NULL) {
                wprintf(L"[!] Razer macro detected: Found 'turbo: true' in the log file. Ban the player.\n");
            }
        }

        fclose(file);
    }
    else {
        return;
    }
}

static void PrintFileModificationTime(const wchar_t* filePath) {
    WIN32_FILE_ATTRIBUTE_DATA fileData;

    if (wcsstr(filePath, L"Glorious Core") != NULL) {
        wprintf(L"[!] Glorious software detected. Open the 'Glorious Core' program and check if any button click contains a macro. If so, ban the player.");
    }

    if (GetFileAttributesExW(filePath, GetFileExInfoStandard, &fileData)) {
        FILETIME lastWriteTime = fileData.ftLastWriteTime;

        // Convert the file's last write time to local time
        FILETIME localLastWriteTime;
        if (FileTimeToLocalFileTime(&lastWriteTime, &localLastWriteTime)) {
            SYSTEMTIME modifiedSystemTime;
            if (FileTimeToSystemTime(&localLastWriteTime, &modifiedSystemTime)) {
                wprintf(L"[!] Macro file detected. Modification time of %s: %d/%d/%d %d:%d:%d. Ban the player if this modification time is just after the tike you freezed the player.\n",
                    filePath,
                    modifiedSystemTime.wYear, modifiedSystemTime.wMonth, modifiedSystemTime.wDay,
                    modifiedSystemTime.wHour, modifiedSystemTime.wMinute, modifiedSystemTime.wSecond);
            }
            else {
                LogError(L"Failed to convert file time to system time");
            }
        }
        else {
            LogError(L"Failed to convert file time to local time");
        }
    }
}

// Function to check recently modified macro files in a folder with a specific extension
static void CheckFilesInFolder(const wchar_t* folderPath, const wchar_t* extension) {
    wchar_t searchPath[MAX_PATH];
    swprintf_s(searchPath, MAX_PATH, L"%s\\*%s", folderPath, extension);

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) { // to avoid crashes
        return;
    }

    do {
        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, MAX_PATH, L"%s\\%s", folderPath, findFileData.cFileName);

        PrintFileModificationTime(fullPath);

    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}

// Function to check for read-only files with a specific extension in a folder
static void CheckReadOnlyFilesWithExtension(const wchar_t* folderPath, const wchar_t* extension) {

    wchar_t searchPath[MAX_PATH];
    swprintf_s(searchPath, MAX_PATH, L"%s\\*%s", folderPath, extension);

    ReplaceUsername(searchPath, MAX_PATH, username);  // Replace username in the search path

    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        wchar_t fullPath[MAX_PATH];
        swprintf_s(fullPath, MAX_PATH, L"%s\\%s", folderPath, findFileData.cFileName);

        ReplaceUsername(fullPath, MAX_PATH, username);  // Replace username in the full path

        // Check if the file has the "read-only" attribute set
        if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0) {
            wprintf(L"[!] Macro file: %s is marked as read-only. Ban the player.\n", fullPath);
        }
    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}

// Start macro checks
void Macros() {
    setConsoleTextColor(BrightBlue);
    wprintf(L"[Macro Scanner] Running checks to detect macro file bypasses...\n");
    wprintf(L"[Macro Scanner] Running checks to detect macro file modifications...\n");
    resetConsoleTextColor();

    DWORD usernameSize = MAX_PATH;
    if (GetUserNameW(username, &usernameSize)) {
        // List of macro file paths to check
        const wchar_t* filePaths[] = {
           L"%appdata%\\Local\\BY-COMBO2",
           L"C:\\Users\\%username%\\AppData\\Local\\Razer\\Synapse3\\Log\\Razer Synapse 3.log",
           L"C:\\Users\\%username%\\AppData\\Local\\LGHUB\\settings.db",
           L"C:\\Users\\%username%\\AppData\\Local\\LGHUB\\setting.db-wal",
           L"C:\\Users\\%username%\\AppData\\Roaming\\steelseries-engine-3-client\\Session Storage\\000003.log",
           L"C:\\Program Files\\AYAX GamingMouse\\record.ini",
           L"C:\\Program Files\\Gaming MouseV30\\record.ini",
           L"%appdata%\\Local\\BY-COMBO\\curid.dct",
           L"%appdata%\\Local\\BY-COMBO\\pro.dct",
           L"C:\\Program Files (x86)\\Bloody7\\Bloody7\\UserLog\\Mouse\\TLcir_9EFF3FF4\\language\\Settings\\EnvironmentVar.ini",
           L"C:\\ProgramData\\Glorious Core\\userdata\\%username%\\data\\MacroDB.db",
           L"C:\\ProgramData\\Glorious Core\\userdata\\%username%\\data\\DevicesDB.db",
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
            int result = swprintf_s(fullPath, MAX_PATH, L"%s", filePaths[i]);
            if (result < 0 || result >= MAX_PATH) {
                LogError(L"Failed to format path"); // Insufficient space for the formatted string or an error occurred during formatting.
                continue;
            }

            ReplaceUsername(fullPath, MAX_PATH, username);
            PrintFileModificationTime(fullPath);
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

        // Check for deleted Razer macros
        wchar_t RazerMacros[MAX_PATH];
        swprintf_s(RazerMacros, MAX_PATH, L"C:\\Users\\%s\\AppData\\Local\\Razer\\Synapse\\log\\macros\\MacrosRazer3.txt", username);
        ReplaceUsername(RazerMacros, MAX_PATH, username);

        SearchForMacroClientDelete(RazerMacros);

        // Check for Razer macros in instance
        const wchar_t* SynapseService = L"C:\\ProgramData\\Razer\\Synapse3\\LogSynapseService.log";

        SearchForTurbo(SynapseService);

        // Check for Logitech macros in instance
        wchar_t dbFilePath[MAX_PATH];
        swprintf_s(dbFilePath, MAX_PATH, L"C:\\Users\\%s\\AppData\\Local\\LGHUB\\settings.db", username);
        wchar_t dbFilePath2[MAX_PATH];
        swprintf_s(dbFilePath2, MAX_PATH, L"C:\\Users\\%s\\AppData\\Local\\LGHUB\\settings.db-wal", username);

        SearchForDurationMS(dbFilePath);
        SearchForDurationMS(dbFilePath2);

        // Check if the macro files are read-only files with specific extensions in their respective macro paths (common bypass)
        CheckReadOnlyFilesWithExtension(L"C:\\Blackweb Gaming AP\\config", L".MA32AIY");
        CheckReadOnlyFilesWithExtension(L"C:\\ProgramData\\Alienware\\AlienWare Command Center\\fxmetadata", L".json");
        CheckReadOnlyFilesWithExtension(L"C:\\Program Files (x86)\\MotoSpeed Gaming Mouse\\V60\\modules\\setting", L".bin");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Local\\LGHUB", L".db");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Local\\LGHUB", L".db-wal");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Local\\Razer\\Synapse3\\Log", L"Razer Synapse 3.log");
        CheckReadOnlyFilesWithExtension(L"C:\\Users\\%username%\\AppData\\Roaming\\steelseries-engine-3-client\\Session Storage", L"000003.log");
        CheckReadOnlyFilesWithExtension(L"C:\\Program Files\\AYAX GamingMouse", L"record.ini");
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
    else {
        return;
    }
}
