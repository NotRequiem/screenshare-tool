#ifndef IMPORT_CODE_HPP
#define IMPORT_CODE_HPP

#include <windows.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>
#include <iomanip>
#include <algorithm>
#include <set>
#include <cctype>

using std::min;

// List of already printed strings, so that the program does not report suspicious strings related to Import Code that were previously reported
static std::set<std::wstring, std::less<std::wstring>, std::allocator<std::wstring>> printedStrings;

void ImportCode();

#endif