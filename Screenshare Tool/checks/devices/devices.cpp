#include "devices.hpp"

// Function to retrieve the system's last logon time
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

    // Release pEnumerator only if it is not null just to avoid compiler warnings
    if (pEnumerator) {
        pEnumerator->Release();
    }

    if (isFirstLogon) {
        return false;
    }

    CoUninitialize();

    return true;
}

// Function to convert FILETIME to a local time string
static void FileTimeToLocalTimeString(const FILETIME& fileTime, std::wstring& localTimeString) {
    // Convert FILETIME to SYSTEMTIME
    SYSTEMTIME systemTime;
    FileTimeToSystemTime(&fileTime, &systemTime);

    // Buffer to store the formatted date
    WCHAR buffer[256];

    // Format the date part (yyyy-MM-dd)
    GetDateFormatEx(
        LOCALE_NAME_USER_DEFAULT,
        0,
        &systemTime,
        L"yyyy-MM-dd",
        buffer,
        sizeof(buffer) / sizeof(buffer[0]),
        nullptr
    );

    // Assign the formatted date to the output string
    localTimeString = buffer;

    // Append the time part (HH:mm:ss)
    GetTimeFormatEx(
        LOCALE_NAME_USER_DEFAULT,
        0,
        &systemTime,
        L"HH:mm:ss",
        buffer,
        sizeof(buffer) / sizeof(buffer[0])
    );

    // Append the formatted time to the output string
    localTimeString.append(L" ").append(buffer);
}

// Function to enumerate subkeys and detect unplugged devices
static void EnumerateSubkeys(const std::wstring& parentKeyPath, const SYSTEMTIME& lastBootTime, int depth = 0) {
    SYSTEMTIME systemTime;

    HKEY hKey;
    LONG result;

    result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        parentKeyPath.c_str(),
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &hKey
    );

    if (result == ERROR_SUCCESS) {
        DWORD index = 0;
        DWORD subkeyNameSize = MAX_PATH;
        WCHAR subkeyName[MAX_PATH]; // Use a fixed-size array to avoid dynamic memory allocation
        static std::unordered_set<std::wstring> flaggedDevices;

        while (RegEnumKeyExW(hKey, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            std::wstring subkeyPath = parentKeyPath + L"\\" + subkeyName;

            // Retrieve the last modified time of the subfolder
            FILETIME subfolderLastModifiedTime = { 0 };
            HKEY subKey;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkeyPath.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &subKey) == ERROR_SUCCESS) {
                RegQueryInfoKeyW(subKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &subfolderLastModifiedTime);

                // Convert FILETIME to local time so that we can make a comparison later
                FILETIME localLastModifiedTime;
                FileTimeToLocalFileTime(&subfolderLastModifiedTime, &localLastModifiedTime);
                FileTimeToSystemTime(&localLastModifiedTime, &systemTime);

                RegCloseKey(subKey);

                // Convert FILETIME to local time string
                std::wstring localTimeString;
                FileTimeToLocalTimeString(localLastModifiedTime, localTimeString);

                // Compare last boot time with the last modified time
                FILETIME ftBootTime;
                SystemTimeToFileTime(&lastBootTime, &ftBootTime);

                // Calculate the time difference in seconds
                ULARGE_INTEGER subfolderTime{};
                subfolderTime.LowPart = localLastModifiedTime.dwLowDateTime;
                subfolderTime.HighPart = localLastModifiedTime.dwHighDateTime;

                ULARGE_INTEGER bootTime{};
                bootTime.LowPart = ftBootTime.dwLowDateTime;
                bootTime.HighPart = ftBootTime.dwHighDateTime;

                ULARGE_INTEGER timeDifference{};
                timeDifference.QuadPart = subfolderTime.QuadPart - bootTime.QuadPart;
                timeDifference.QuadPart /= 10000000; // Convert 100-nanosecond intervals to seconds

                // Check if the last write time is significantly after the last boot time
                const int thresholdSeconds = 10;
                if (localLastModifiedTime.dwHighDateTime > ftBootTime.dwHighDateTime && static_cast<int>(timeDifference.QuadPart) > thresholdSeconds) {
                    // Extract the relevant part of the key path
                    size_t pos = subkeyPath.find(L"USB\\");
                    if (pos != std::wstring::npos) {
                        subkeyPath = subkeyPath.substr(pos + 4); // Exclude "USB\" from the path
                    }

                    // Check if this device has already been flagged
                    if (flaggedDevices.find(subkeyPath.substr(0, 17)) == flaggedDevices.end()) {
                        std::wcout << "[!] Warning: Unplugged device detected:  " << subkeyPath << ". Ban the user." << std::endl;
                        std::wcout << "    Device was unplugged at: " << localTimeString << std::endl;

                        // Add the device to the flagged set
                        flaggedDevices.insert(subkeyPath.substr(0, 17));
                    }
                }
            }

            // Recursively enumerate subkeys of the current subkey if depth is not reached
            if (depth > 0) {
                EnumerateSubkeys(subkeyPath, lastBootTime, depth - 1);
            }

            index++;
            subkeyNameSize = MAX_PATH;
        }

        RegCloseKey(hKey);
    }
}

// Function to check for unplugged devices
void UnpluggedDevices() {
    setConsoleTextColor(BrightGreen);
    std::wcout << "[Device Scanner] Running checks for unplugged devices...\n";
    resetConsoleTextColor();

    std::wstring parentKeyPath = L"SYSTEM\\ControlSet001\\Enum\\USB";

    // Get the system's last boot time
    SYSTEMTIME lastBootTime{};
    Logon(lastBootTime);

    // Call EnumerateSubkeys with the last boot time and one level depth (so that we can detect unplugged usbs)
    EnumerateSubkeys(parentKeyPath, lastBootTime, 1);
}
