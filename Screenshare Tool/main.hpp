#ifndef MAIN_H
#define MAIN_H

// Virtual Machine checks
#include "virtual machines\vmaware.hpp"

// Disk replaces checks
#include "disk\disk.hpp"

// Code import checks
#include "import code\importcode.hpp"

// Task Scheduler checks
#include "task scheduler\scheduler.hpp"

// Digital signature checks
#include "digital signature\trustverify.hpp"

// WMI related headers
#include "WMI\wmi.hpp"

// File execution checks
#include "memory\kernelproc.hpp"
#include "memory\userproc.hpp"

// Mods checks
#include "mods\mods.h"

// GUI related headers
#include "gui\color.hpp"

// Eventlog checks
#include "eventlog\evtquery.hpp"
#include "eventlog\evthandler.hpp"

// Device checks
#include "devices\devices.hpp"
#include "devices\mouse.hpp"

// USN Journal processing headers
#include "usn journal\journal.hpp"
#include "usn journal\fsutil.hpp"

// Macros and onboard memory macros checks
#include "macros\macroscanner.hpp"
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

// Checks if the sreenshare tool is running under a Virtual Machine:
void VirtualMachine() {
    bool isVM = VM::detect();

    if (isVM) {
        std::cout << "WARNING: Virtual Machine detected: " << VM::brand() << ". This is considered bannable." << std::endl;
    }
}

void checkMemoryExe() {
    std::wstring programName = L"memory.exe";
    std::filesystem::path programPath = std::filesystem::current_path() / programName;

    if (!std::filesystem::exists(programPath)) {
        std::wcerr << programName << L" not found in the current working directory. Download it at: https://github.com/NotRequiem/memscanner/releases/download/memscanner/memory.exe" << std::endl;
    }
}

#endif
