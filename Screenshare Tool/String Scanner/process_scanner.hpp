#ifndef PROCESS_SCANNER_H
#define PROCESS_SCANNER_H

#include <iostream>
#include <tlhelp32.h>
#include <windows.h>
#include <string>
#include <regex>

void scanProcessStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex);

#endif
