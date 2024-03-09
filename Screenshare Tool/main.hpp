#pragma once

// .h = C header file
// .hpp = C++ header file

/* 
   ================================================================================================
                                     // Miscellaneous headers  //
   ================================================================================================
*/ 

/* WMI related headers
"miscellaneous\WMI\wmi.hpp"

// Digital signature headers
"miscellaneous\digital signature\trustverify.hpp"

// GUI related headers
"miscellaneous\string\string.hpp"
"miscellaneous\gui\color.h"
*/

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

// Forensic checks
#include "checks\forensic\prefetch.hpp"
#include "checks\forensic\appcrash.hpp"
#include "checks\forensic\recentfiles.hpp"

// Localhost environment checks
#include "checks\system\localhost.h"

// File execution checks
#include "checks\memory\kernelproc.hpp"
#include "checks\memory\userproc.hpp"

// Internal cheat checks
#include "checks\memory\javaw.h"

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
#include "checks\mods\xray.hpp"
#include "checks\mods\mods.h"

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
