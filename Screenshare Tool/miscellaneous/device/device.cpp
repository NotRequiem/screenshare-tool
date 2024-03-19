#include "device.hpp"

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

// Format is: \\Device\\HarddiskVolume(number)
std::wstring ConvertDevicePathToFilePath(const std::wstring& devicePath)
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