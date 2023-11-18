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

class ImportCodeDetector {
public:
    static void RunImportCodeChecks();
    
private:
    static void DetectImportCode(DWORD pid);

    static std::set<std::wstring, std::less<std::wstring>, std::allocator<std::wstring>> printedStrings;
};

#endif