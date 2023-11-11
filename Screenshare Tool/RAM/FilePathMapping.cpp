#include "FilePathMapping.hpp"


// Converts device paths to paths with drive letters
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
