#include "prefetch.hpp"

// Function to check if a digital signature of an executed file is valid
static bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

static std::wstring GetDriveLetterFromVolumePath(const std::wstring& volumePath) {
    wchar_t driveStrings[255];
    wchar_t* driveLetter;

    // Get a list of all the logical drives
    DWORD success = GetLogicalDriveStringsW(sizeof(driveStrings) / sizeof(driveStrings[0]), driveStrings);

    if (success > 0) {
        driveLetter = driveStrings;

        // Check for specific strings in volumePath
        if (volumePath.find(L"PROGRAM FILES") != std::wstring::npos ||
            volumePath.find(L"SYMBOLS") != std::wstring::npos ||
            volumePath.find(L"USERS") != std::wstring::npos ||
            volumePath.find(L"WINDOWS") != std::wstring::npos ||
            volumePath.find(L"PROGRAMDATA") != std::wstring::npos ||
            volumePath.find(L"XBOXGAMES") != std::wstring::npos) {
            // Return C:\ if one of the specified strings is present
            return L"C:\\";
        }
        else {
            // Count the number of drives
            std::vector<std::wstring> driveLetters;
            while (*driveLetter) {
                driveLetters.push_back(driveLetter);
                driveLetter += wcslen(driveLetter) + 1;
            }

            // Return the other disk letter if there are only two drives
            if (driveLetters.size() == 2) {
                std::wstring otherDrive = (driveLetters[0] == volumePath.substr(0, 3)) ? driveLetters[1] : driveLetters[0];
                return otherDrive + L"\\";
            }
            else {
                // Return (UnknownDisk) if there are more than two drives
                return L"(UnknownDisk)\\";
            }
        }
    }

    // Return the original volume path if no matching drive letter is found
    return volumePath;
}

// Function to check for bypasses in the Prefetch folder
static void CheckPrefetchReadOnlyAttribute(const std::wstring& prefetchFilePath) {
    DWORD fileAttributes = GetFileAttributesW(prefetchFilePath.c_str());

    if (fileAttributes != INVALID_FILE_ATTRIBUTES) {
        if ((fileAttributes & FILE_ATTRIBUTE_READONLY) != 0) {
            std::wcout << L"[!] Prefetch file is marked as read-only: " << prefetchFilePath << L". This is bannable." << std::endl;
        }
    }
}

void Prefetch(bool imp) {
    SYSTEMTIME lastLogonTime;

    if (!LogonTime(lastLogonTime)) {
        std::cerr << "Failed to retrieve last logon time." << std::endl;
        return;
    }

    std::wstring prefetchDir = L"C:\\Windows\\Prefetch\\";
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((prefetchDir + L"*").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Prefetch directory not found. Ensure that C:\\Windows\\Prefetch\\ exists and ban the player if not." << std::endl;
        return;
    }

    if (!imp) {
        setConsoleTextColor(Magenta);
        std::wcout << "[Forensic Scanner] Running checks to detect renamed and deleted Prefetch folders...\n";
        std::wcout << "[Forensic Scanner] Running checks to detect Prefetch bypasses...\n";
        std::wcout << "[Forensic Scanner] Running checks to detect executed files with Prefetch...\n";
        resetConsoleTextColor();
    }

    std::unordered_set<std::wstring> printedPaths;  // Unordered set to store printed paths

    do {
        if (findFileData.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY) {
            std::wstring prefetchFile = findFileData.cFileName;

            // Check if the prefetch file name contains ".exe" (case-insensitive)
            if (prefetchFile.find(L".EXE") == std::wstring::npos) {
                continue;  // Skip files that do not contain ".exe"
            }

            std::wstring prefetchFilePath = prefetchDir + prefetchFile;

            // Check the read-only attribute of prefetch files
            CheckPrefetchReadOnlyAttribute(prefetchFilePath);

            FILETIME lastWriteTime;
            FileTimeToLocalFileTime(&findFileData.ftLastWriteTime, &lastWriteTime);

            SYSTEMTIME st;
            FileTimeToSystemTime(&lastWriteTime, &st);

            FILETIME lastLogonFileTime;
            SystemTimeToFileTime(&lastLogonTime, &lastLogonFileTime);

            if (CompareFileTime(&lastWriteTime, &lastLogonFileTime) > 0) {
                std::wstring fullFilePathW = prefetchDir + prefetchFile;

                int bufferSize = WideCharToMultiByte(CP_UTF8, 0, fullFilePathW.c_str(), -1, nullptr, 0, nullptr, nullptr);
                std::string fullFilePath(bufferSize, 0);
                WideCharToMultiByte(CP_UTF8, 0, fullFilePathW.c_str(), -1, &fullFilePath[0], bufferSize, nullptr, nullptr);

                const auto parser = prefetch_parser(fullFilePath);
                if (!parser.success()) {
                    continue;
                }
                else {
                    for (const auto& filename : parser.get_filenames_strings()) {
                        // Extract the file name from the prefetch file name (assuming a consistent format)
                        std::wstring prefetchFileName = findFileData.cFileName;
                        size_t hyphenPos = prefetchFileName.find(L'-');
                        std::wstring fileNameFromPrefetch = (hyphenPos != std::wstring::npos) ? prefetchFileName.substr(0, hyphenPos) : prefetchFileName;

                        // Convert volume path to proper path with disk letter
                        std::wstring properPath = GetDriveLetterFromVolumePath(filename) + filename.substr(35); // 35 is the character length of the Volume ID

                        // Check if the properPath contains the name of the file from the prefetch file
                        if (properPath.find(fileNameFromPrefetch) != std::wstring::npos) {
                            // Check if the path has already been printed or ends with ".EXE"
                            if (!screenshare_tool::FileTracker::isFileProcessed(properPath) && properPath.length() >= 4 && properPath.substr(properPath.length() - 4) == L".EXE") {
                                // Check if properPath contains "UnknownDisk"
                                if (properPath.find(L"UnknownDisk") != std::wstring::npos) {
                                    std::wcout << L"[#] Executed file: " << properPath << std::endl;
                                }
                                else {
                                    // Call IsFileSignatureValid only if properPath doesn't contain "UnknownDisk"
                                    if (!IsFileSignatureValid(properPath)) {
                                        std::wcout << L"[#] Executed & Unsigned file: " << properPath << std::endl;
                                    }
                                }
                                // Add to the FileTracker to avoid duplicate output
                                screenshare_tool::FileTracker::addProcessedFile(properPath);
                            }
                        }
                    }
                }
            }
        }

    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}
