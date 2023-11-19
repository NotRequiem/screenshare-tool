#ifndef PROCESS_SCANNER_H
#define PROCESS_SCANNER_H

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <regex>
#include <set>

void scanProcessStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex);

#endif
