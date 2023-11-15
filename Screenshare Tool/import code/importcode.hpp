#ifndef IMPORT_CODE_HPP
#define IMPORT_CODE_HPP

#include <windows.h>
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iomanip>

class ImportCodeDetector {
public:
    static void RunImportCodeChecks();
    
private:
    static bool isStringChar(unsigned char ch);
    static void DetectImportCode(DWORD pid);
    static DWORD GetPIDForClipboardUserService();
};

#endif