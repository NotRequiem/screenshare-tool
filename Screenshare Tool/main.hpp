#pragma once

// Virtual Machine checks
#include "virtual machines\vmaware.hpp"

// Disk replaces checks
#include "disk\disk.hpp"

// WMI related headers
#include "WMI\wmi.hpp"

// Code import checks
#include "import code\importcode.hpp"

// Task Scheduler checks
#include "task scheduler\scheduler.hpp"

// Digital signature checks
#include "digital signature\trustverify.hpp"

// File execution checks
#include "memory\kernelproc.hpp"
#include "memory\userproc.hpp"

// Mods checks
#include "mods\mods.h"

// GUI related headers
#include "gui\color.h"

// BAM checks
#include "system\bam.hpp"

// String cleaners checks
#include "system\prochacker.hpp"

// Restarted processes checks
#include "system\prochandler.hpp"

// Eventlog checks
#include "system\evtquery.hpp"
#include "system\evthandler.hpp"

// Device checks
#include "devices\devices.hpp"
#include "devices\mouse.hpp"
#include "devices\keys.h"

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

// Checks if the memory scanner is present:
void checkMemoryExe() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);

    std::filesystem::path exePath(buffer);
    std::filesystem::path memoryExePath = exePath.parent_path() / L"memory.exe";

    if (!std::filesystem::exists(memoryExePath)) {
        std::wcerr << L"Download 'memory.exe' at: https://github.com/NotRequiem/memscanner/releases/download/memscanner/memory.exe and place it near the Screenshare Tool program." << std::endl;
    }
}