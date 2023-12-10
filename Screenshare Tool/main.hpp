#pragma once

// .h = C header file
// .hpp = C++ header file

/* 
   ================================================================================================
                                     // Miscellaneous headers  //
   ================================================================================================
*/ 

// WMI related headers
#include "miscellaneous\WMI\wmi.hpp"

// Digital signature headers
#include "miscellaneous\digital signature\trustverify.hpp"

// GUI related headers
#include "miscellaneous\gui\color.h"

/*
   ================================================================================================
                                     // Detection headers  //
   ================================================================================================
*/

// Virtual Machine checks
#include "checks\virtual machines\vmaware.hpp"

// Disk replaces checks
#include "checks\disk\disk.hpp"

// Code import checks
#include "checks\import code\importcode.hpp"

// Task Scheduler checks
#include "checks\task scheduler\scheduler.hpp"

// BAM checks
#include "checks\bam\bam.hpp"

// String cleaners checks
#include "checks\system\prochacker.hpp"

// Restarted processes checks
#include "checks\system\prochandler.hpp"

// File execution checks
#include "checks\memory\kernelproc.hpp"
#include "checks\memory\userproc.hpp"

// Eventlog checks
#include "checks\eventlog\evtquery.hpp"
#include "checks\eventlog\evthandler.hpp"

// USN Journal processing headers
#include "checks\usn journal\journal.hpp"
#include "checks\usn journal\fsutil.hpp"

// Device checks
#include "checks\devices\devices.hpp"
#include "checks\devices\mouse.hpp"
#include "checks\devices\keys.h"

// Macros and onboard memory macros checks
#include "checks\macros\macroscanner.hpp"
#include "checks\macros\macros.h"
#include "checks\onboard memory macros\mousehook.h"
#include "checks\onboard memory macros\keyboardhook.h"

// Mods checks
#include "checks\mods\mods.h"

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