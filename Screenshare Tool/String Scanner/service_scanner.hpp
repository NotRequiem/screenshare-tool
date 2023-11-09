#ifndef PROCESS_SCANNER_HPP
#define PROCESS_SCANNER_HPP

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <regex>

void scanServiceStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex);

#endif
