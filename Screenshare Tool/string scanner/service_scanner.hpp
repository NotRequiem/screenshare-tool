#ifndef SERVICE_SCANNER_HPP
#define SERVICE_SCANNER_HPP

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <regex>

void EnableServiceDebugPrivilege();
void scanServiceStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex);

#endif
