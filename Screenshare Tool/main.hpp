#ifndef MAIN_H
#define MAIN_H

// Virtual Machine checks
#include "virtual machines\vmaware.hpp"

// Disk replaces checks
#include "disk\diskchk.hpp"

// Code import checks
#include "import code\importcode.hpp"

// Task Scheduler checks
#include "task scheduler\scheduler.hpp"

// Digital signature checks
#include "digital signature\trustverify.hpp"

// WMI related headers
#include "WMI\wmi.hpp"

// DLL Injection checks
#include "csrss\csrss.hpp"

// Mods checks
#include "javaw\mods.h"

// Device checks
#include "devices\devices.hpp"
#include "devices\mouse.hpp"

// Process memory string scanning headers
#include "string scanner\process_scanner.hpp"
#include "string scanner\service_scanner.hpp"

// USN Journal processing headers
#include "usn journal\journal.hpp"
#include "usn journal\fsutil.h"

// Macros and onboard memory macros checks
#include "macros\macros.h"
#include "onboard memory macros\mousehook.h"
#include "onboard memory macros\keyboardhook.h"

// Check if the sreenshare tool has administrator privileges:
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
        if (!CheckTokenMembership(NULL, AdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(AdminGroup);
    }
    return isAdmin;
}

// Enables Debug privileges to scan certain processes in search of bypasses and cheats:
void EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp{};

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                if (GetLastError() != ERROR_SUCCESS) {
                    std::cerr << "AdjustTokenPrivileges failed with error code: " << GetLastError() << std::endl;
                }
            } else {
                std::cerr << "AdjustTokenPrivileges failed with error code: " << GetLastError() << std::endl;
            }
        } else {
            std::cerr << "LookupPrivilegeValue failed with error code: " << GetLastError() << std::endl;
        }

        CloseHandle(hToken);
    } else {
        std::cerr << "OpenProcessToken failed with error code: " << GetLastError() << std::endl;
    }
}

void VirtualMachine() {
    bool isVM = VM::detect();

    if (isVM) {
        std::cout << "WARNING: Virtual Machine detected: " << VM::brand() << std::endl;
    }
}

#endif
