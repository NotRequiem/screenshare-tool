#include "prefetch.hpp"

// Function to check if a file executed with Task Scheduler is valid
static bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

static bool Logon(SYSTEMTIME& lastLogonTime) {
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    HRESULT hres;

    // Initialize COM with only 1 thread to avoid problems with the service name wmi query
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres)) {
        return false;
    }

    hres = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr
    );

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // Obtain the initial locator to WMI
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&pLoc)
    );

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr,
        nullptr,
        0,
        0,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IEnumWbemClassObject* pEnumerator = nullptr;

    hres = pSvc->ExecQuery(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM Win32_LogonSession WHERE LogonType = 2"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hres)) {
        return false;
    }

    FILETIME maxLogonFileTime = {};
    bool isFirstLogon = true;

    while (pEnumerator) {
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (uReturn == 0) {
            break;
        }

        VARIANT vtProp;
        VariantInit(&vtProp);

        // Use the previously assigned hres
        if (SUCCEEDED(hres)) {
            hres = pclsObj->Get(L"StartTime", 0, &vtProp, 0, 0);

            if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) {
                SYSTEMTIME logonTime{};
                swscanf_s(vtProp.bstrVal, L"%4hd%2hd%2hd%2hd%2hd%2hd",
                    &logonTime.wYear, &logonTime.wMonth, &logonTime.wDay,
                    &logonTime.wHour, &logonTime.wMinute, &logonTime.wSecond);

                FILETIME logonFileTime;
                SystemTimeToFileTime(&logonTime, &logonFileTime);

                if (isFirstLogon || CompareFileTime(&logonFileTime, &maxLogonFileTime) > 0) {
                    maxLogonFileTime = logonFileTime;
                    lastLogonTime = logonTime;
                    isFirstLogon = false;
                }
            }
        }

        VariantClear(&vtProp);
        pclsObj->Release();
    }

    if (pEnumerator) {
        pEnumerator->Release();
    }

    if (isFirstLogon) {
        return false;
    }

    CoUninitialize();

    return true;
}

static std::wstring GetDriveLetterFromVolumePath(const std::wstring& volumePath) {
    wchar_t driveStrings[255];
    wchar_t* driveLetter;

    // Add "\\?\" prefix to the volume path
    std::wstring fullVolumePath = L"\\\\?\\" + volumePath;

    // Get a list of all the logical drives
    DWORD success = GetLogicalDriveStringsW(sizeof(driveStrings) / sizeof(driveStrings[0]), driveStrings);

    if (success > 0) {
        driveLetter = driveStrings;

        while (*driveLetter) {
            // Check if the volume ID matches with the current drive
            if (GetVolumeNameForVolumeMountPointW(driveLetter, &fullVolumePath[0], MAX_PATH)) {
                // Replace the original volume path with the drive letter
                return driveLetter;
            }

            // Go to the next drive
            driveLetter += wcslen(driveLetter) + 1;
        }
    }

    // Return the original volume path if no matching drive letter is found
    return volumePath;
}

void Prefetch() {
    SYSTEMTIME lastLogonTime;

    if (!Logon(lastLogonTime)) {
        std::cerr << "Failed to retrieve last logon time." << std::endl;
        return;
    }

    std::wstring prefetchDir = L"C:\\Windows\\Prefetch\\";
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW((prefetchDir + L"*").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Prefetch directory not found. Ensure that you can access C:\\Windows\\Prefetch\\ and ban the player if you can't." << std::endl;
        return;
    }

    setConsoleTextColor(Magenta);
    std::wcout << "[Forensic Scanner] Running checks to detect executed files with Prefetch...\n";
    resetConsoleTextColor();
    std::unordered_set<std::wstring> printedPaths;  // Unordered set to store printed paths

    do {
        if (findFileData.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY) {
            std::wstring prefetchFile = findFileData.cFileName;

            // Check if the prefetch file name contains ".exe" (case-insensitive)
            if (prefetchFile.find(L".EXE") == std::wstring::npos) {
                continue;  // Skip files that do not contain ".exe"
            }

            std::wstring prefetchFilePath = prefetchDir + prefetchFile;

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
                        std::wstring properPath = GetDriveLetterFromVolumePath(filename) + filename.substr(35);

                        // Check if the properPath contains the name of the file from the prefetch file
                        if (properPath.find(fileNameFromPrefetch) != std::wstring::npos && !IsFileSignatureValid(properPath)) {
                            // Check if the path has already been printed or ends with ".EXE"
                            if (printedPaths.find(properPath) == printedPaths.end() && properPath.length() >= 4 && properPath.substr(properPath.length() - 4) == L".EXE") {
                                std::wcout << L"\t[#] Executed & Unsigned file since last boot: " << properPath << std::endl;
                                printedPaths.insert(properPath);  // Add the path to the set
                            }

                        }
                    }
                }
            }
        }

    } while (FindNextFileW(hFind, &findFileData) != 0);

    FindClose(hFind);
}
