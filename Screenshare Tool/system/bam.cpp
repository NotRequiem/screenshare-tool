#include "bam.hpp"

std::map<std::wstring, std::wstring> GetDosPathDevicePathMap()
{
    wchar_t devicePath[MAX_PATH] = { 0 };
    std::map<std::wstring, std::wstring> result;
    std::wstring dosPath = L"A:";

    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter)
    {
        dosPath[0] = letter;
        if (QueryDosDeviceW(dosPath.c_str(), devicePath, MAX_PATH))
        {
            result[dosPath] = devicePath;
        }
    }
    return result;
}

// Function to check if a file signature is valid
static bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

static std::wstring ConvertDevicePathToFilePath(const std::wstring& devicePath)
{
    static std::map<std::wstring, std::wstring> dosPathDevicePathMap = GetDosPathDevicePathMap();

    for (const auto& mapping : dosPathDevicePathMap)
    {
        if (devicePath.find(mapping.second) == 0)
        {
            return mapping.first + devicePath.substr(mapping.second.length());
        }
    }

    return devicePath; // Return original if no match is found
}

void ListBinaryRegistryValues(HKEY hKey, const char* subKey);

static void ConvertFileTimeToLocalTime(const FILETIME& fileTime, SYSTEMTIME& localTime)
{
    FileTimeToSystemTime(&fileTime, &localTime);
}

static bool LogonTime(SYSTEMTIME& lastLogonTime) {
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

        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pEnumerator->Release();

    if (isFirstLogon) {
        return false;
    }

    CoUninitialize();

    return true;
}


void ListBinaryValuesRecursively(HKEY hKey, const char* subKey) {
    HKEY keyHandle;
    if (RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &keyHandle) == ERROR_SUCCESS) {
        DWORD subKeyCount;
        LSTATUS result;

        result = RegQueryInfoKeyA(keyHandle, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        if (result == ERROR_SUCCESS) {
            for (DWORD i = 0; i < subKeyCount; i++) {
                DWORD subKeyNameSize = 256;
                std::unique_ptr<char[]> subKeyName;

                do {
                    subKeyName = std::make_unique<char[]>(subKeyNameSize);
                    result = RegEnumKeyExA(keyHandle, i, subKeyName.get(), &subKeyNameSize, NULL, NULL, NULL, NULL);
                } while (result == ERROR_MORE_DATA);

                if (result == ERROR_SUCCESS) {
                    ListBinaryRegistryValues(keyHandle, subKeyName.get());
                }
            }
        }

        RegCloseKey(keyHandle);
    }
}

void ListBinaryRegistryValues(HKEY hKey, const char* subKey) {
    HKEY keyHandle;
    if (RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &keyHandle) == ERROR_SUCCESS) {
        DWORD maxValueNameSize, maxValueDataSize;
        DWORD index = 0;
        LSTATUS result;

        result = RegQueryInfoKeyA(keyHandle, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &maxValueNameSize, &maxValueDataSize, NULL, NULL);

        if (result == ERROR_SUCCESS) {
            maxValueNameSize++; // To include the null terminator
            std::unique_ptr<char[]> valueName = std::make_unique<char[]>(maxValueNameSize);

            if (valueName != nullptr) {
                std::unique_ptr<BYTE[]> valueData = std::make_unique<BYTE[]>(maxValueDataSize);

                if (valueData != nullptr) {
                    while (1) {
                        DWORD valueNameSize = maxValueNameSize;
                        DWORD valueType;
                        DWORD valueDataSize = maxValueDataSize;

                        result = RegEnumValueA(keyHandle, index, valueName.get(), &valueNameSize, NULL, &valueType, valueData.get(), &valueDataSize);

                        if (result == ERROR_NO_MORE_ITEMS) {
                            break;
                        }

                        if (result == ERROR_SUCCESS && valueType == REG_BINARY) {
                            if (strstr(valueName.get(), "\\Device\\") != nullptr) {
                                std::wstring devicePath(valueName.get(), valueName.get() + valueNameSize);

                                // Convert binary data to FILETIME structure
                                FILETIME fileTime;
                                memcpy(&fileTime, valueData.get(), sizeof(FILETIME));

                                // Convert FILETIME to local SYSTEMTIME
                                SYSTEMTIME localTime;
                                ConvertFileTimeToLocalTime(fileTime, localTime);

                                // Check if local time is after the last logon time
                                SYSTEMTIME lastLogonTime{};
                                if (LogonTime(lastLogonTime)) {
                                    FILETIME lastLogonFileTime;
                                    SystemTimeToFileTime(&lastLogonTime, &lastLogonFileTime);

                                    // Check if local time is after the last logon time
                                    if (CompareFileTime(&fileTime, &lastLogonFileTime) > 0) {
                                        // Check if the file signature is valid
                                        if (!IsFileSignatureValid(ConvertDevicePathToFilePath(devicePath))) {
                                            std::wcout << "[#] Executed & Unsigned file: " << ConvertDevicePathToFilePath(devicePath)
                                                << " at: " << localTime.wYear << L" - " << localTime.wMonth << L" - " << localTime.wDay
                                                << L" " << localTime.wHour << L":" << localTime.wMinute << L":" << localTime.wSecond << std::endl;
                                        }
                                    }
                                }
                            }
                        }

                        index++;
                    }
                }
            }

            RegCloseKey(keyHandle);

            // Recursively search for binary values in subkeys
            ListBinaryValuesRecursively(hKey, subKey);
        }
    }
}

void bam() {
    setConsoleTextColor(Gray);
    std::wcout << "[System Scanner] Running checks to detect executed files with BAM... " << std::endl;
    resetConsoleTextColor();

    HKEY hKey = HKEY_LOCAL_MACHINE;
    const char* subKey = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";

    ListBinaryValuesRecursively(hKey, subKey);
}