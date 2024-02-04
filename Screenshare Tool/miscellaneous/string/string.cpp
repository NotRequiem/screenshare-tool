#include "string.hpp"

// Function to convert std::wstring to UTF-8 std::string
std::string convertWStringToUtf8(const std::wstring& wstr) {
    int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string utf8String(utf8Length, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &utf8String[0], utf8Length, nullptr, nullptr);
    return utf8String;
}