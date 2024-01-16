#include "bam.hpp"

static std::map<std::wstring, std::wstring> GetDosPathDevicePathMap()
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

static void ListBinaryValuesRecursively(HKEY hKey, const wchar_t* subKey) {
    HKEY keyHandle;
    if (RegOpenKeyExW(hKey, subKey, 0, KEY_READ, &keyHandle) == ERROR_SUCCESS) {
        DWORD subKeyCount;
        LSTATUS result;

        result = RegQueryInfoKeyW(keyHandle, NULL, NULL, NULL, &subKeyCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

        if (result == ERROR_SUCCESS) {
            for (DWORD i = 0; i < subKeyCount; i++) {
                DWORD subKeyNameSize = 256;
                std::unique_ptr<wchar_t[]> subKeyName;

                do {
                    subKeyName = std::make_unique<wchar_t[]>(subKeyNameSize);
                    result = RegEnumKeyExW(keyHandle, i, subKeyName.get(), &subKeyNameSize, NULL, NULL, NULL, NULL);
                } while (result == ERROR_MORE_DATA);

                if (result == ERROR_SUCCESS) {
                    ListBinaryRegistryValues(keyHandle, subKeyName.get());
                }
            }
        }

        RegCloseKey(keyHandle);
    }
}

void ListBinaryRegistryValues(HKEY hKey, const wchar_t* subKey) {
    HKEY keyHandle;
    if (RegOpenKeyExW(hKey, subKey, 0, KEY_READ, &keyHandle) == ERROR_SUCCESS) {
        DWORD maxValueNameSize, maxValueDataSize;
        DWORD index = 0;
        LSTATUS result;

        result = RegQueryInfoKeyW(keyHandle, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &maxValueNameSize, &maxValueDataSize, NULL, NULL);

        if (result == ERROR_SUCCESS) {
            maxValueNameSize++; // To include the null terminator
            std::unique_ptr<wchar_t[]> valueName = std::make_unique<wchar_t[]>(maxValueNameSize);

            if (valueName != nullptr) {
                std::unique_ptr<BYTE[]> valueData = std::make_unique<BYTE[]>(maxValueDataSize);

                if (valueData != nullptr) {
                    while (1) {
                        DWORD valueNameSize = maxValueNameSize;
                        DWORD valueType;
                        DWORD valueDataSize = maxValueDataSize;

                        result = RegEnumValueW(keyHandle, index, valueName.get(), &valueNameSize, NULL, &valueType, valueData.get(), &valueDataSize);

                        if (result == ERROR_NO_MORE_ITEMS) {
                            break;
                        }

                        if (result == ERROR_SUCCESS && valueType == REG_BINARY) {
                            if (wcsstr(valueName.get(), L"\\Device\\") != nullptr) {
                                std::wstring devicePath(valueName.get(), valueName.get() + valueNameSize);

                                // Convert binary data to FILETIME structure
                                FILETIME fileTime;
                                memcpy(&fileTime, valueData.get(), sizeof(FILETIME));

                                // Convert FILETIME to local SYSTEMTIME
                                SYSTEMTIME utcTime;
                                FileTimeToSystemTime(&fileTime, &utcTime);

                                // Convert local SYSTEMTIME to local FILETIME
                                SYSTEMTIME localTime;
                                SystemTimeToTzSpecificLocalTime(nullptr, &utcTime, &localTime);

                                // Check if local time is after the last logon time
                                SYSTEMTIME lastLogonTime{};
                                if (LogonTime(lastLogonTime)) {
                                    FILETIME lastLogonFileTime;
                                    SystemTimeToFileTime(&lastLogonTime, &lastLogonFileTime);

                                    // Check if local time is after the last logon time
                                    if (CompareFileTime(&fileTime, &lastLogonFileTime) > 0) {
                                        // Check if the file signature is valid
                                        if (!IsFileSignatureValid(ConvertDevicePathToFilePath(devicePath))) {
                                            std::wcout << L"[#] Executed & Unsigned file: " << ConvertDevicePathToFilePath(devicePath)
                                                << L" at: " << localTime.wYear << L"/" << std::setw(2) << std::setfill(L'0') << localTime.wMonth
                                                << L"/" << std::setw(2) << std::setfill(L'0') << localTime.wDay
                                                << L" " << std::setw(2) << std::setfill(L'0') << localTime.wHour
                                                << L":" << std::setw(2) << std::setfill(L'0') << localTime.wMinute
                                                << L":" << std::setw(2) << std::setfill(L'0') << localTime.wSecond << L'\n';
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
    setConsoleTextColor(DarkCyan);
    std::wcout << L"[BAM Scanner] Running checks to detect executed files with BAM...\n";
    resetConsoleTextColor();

    HKEY hKey = HKEY_LOCAL_MACHINE;
    const wchar_t* subKey = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";

    ListBinaryValuesRecursively(hKey, subKey);
}
