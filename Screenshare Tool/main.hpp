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

// Checks if the Screenshare Tool is running under a Virtual Machine.
// If the tool is not running in import mode, it performs checks to detect virtual machines.
// This function utilizes the VM namespace to detect virtual machine presence and brand.
void VirtualMachine(bool imp) {
    if (!imp) {
        setConsoleTextColor(White);
        std::wcout << L"[Virtual Machine Scanner] Running checks to detect virtual machines...\n";
        resetConsoleTextColor();
    }

    // Detect virtual machine presence and retrieve its brand information
    bool isVM = VM::detect();
    if (isVM) {
        if (VM::brand() != "Unknown") {
            std::cout << "[!] Virtual Machine detected: " << VM::brand() << ". This is considered bannable." << std::endl;
        }
    }
}

// Checks if the memory scanner (memory.exe) is present.
// If memory.exe is not found in the same directory as the Screenshare Tool program,
// it prompts the user to download and place memory.exe accordingly.
void checkMemoryExe() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);

    std::filesystem::path exePath(buffer);
    std::filesystem::path memoryExePath = exePath.parent_path() / L"memory.exe";

    if (!std::filesystem::exists(memoryExePath)) {
        std::wcerr << L"Download 'memory.exe' at: https://github.com/NotRequiem/memscanner/releases/download/memscanner/memory.exe and place it near the Screenshare Tool program." << std::endl;
        std::system("pause");
    }
}

// Checks the processor architecture of the system.
// If the Screenshare Tool is running as a 32-bit application on a 64-bit system,
// it prompts the user to use the 64-bit version of the tool for optimal performance.
void CheckProcessorArchitecture() {
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    if (isWow64) {
        std::wcout << L"You are running a 32-bit version of this Screenshare Tool on a 64-bit system." << std::endl;
        std::wcout << L"It is recommended to use the 64-bit version: https://github.com/NotRequiem/screenshare-tool/releases/tag/screenshare-tool" << std::endl;
        system("pause");
    }
}

// Installs hardware hooks to detect onboard memory macros.
// This function utilizes InstallMouseHook and InstallKeyboardHook functions to install hooks,
// then enters a loop to process messages until the delete key is pressed.
// Upon exiting the loop, it uninstalls the hooks.
void ExecuteHookCode() {
    if (InstallMouseHook() && InstallKeyboardHook()) {
        MSG msg;
        while (!GetAsyncKeyState(VK_DELETE)) {
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }

        UninstallMouseHook();
        UninstallKeyboardHook();
    }
}

void StartTool() {
    // Set the locale for wide character support
    if (setlocale(LC_ALL, ".UTF-8") == nullptr) {
        std::cerr << "Failed to set UTF-8 locale." << std::endl;
    }

    CheckProcessorArchitecture(); // Checks if you're running the 32-bit version of the tool in a 64 bit system
    checkMemoryExe(); // Checks if the memory scanner is present   
}


// ================================================================================================
//                                    SCREENSHARE TOOL CHECKS
// ================================================================================================

/*
        MacroStrings(imp); // Checks for macro strings. This should run first because macro strings are fastly erased

        ExecutedFiles(imp); // Checks executed files using several processes

        USNJournalCleared(imp); // Check if USNJournal was cleared

        SystemTimeChange(imp); // Checks if the system time was changed

        SystemInformer(imp); // Checks if System Informer or Process Hacker were executed

        RestartedProcesses(imp); // Checks if certain processes needed to check for certain bypasses and file executions are restarted

        EventlogBypass(imp); // Checks if eventlog was bypassed

        LocalHost(); // Checks if there is a networh shared drive that could contain cheat files

        bam(imp); // Checks executed files with the Background Activity Moderator

        SuspiciousMods(); // Checks for mods that were modified while Minecraft was running

        ReplacedDisks(imp); // Checks physical or virtual disks replaced or formatted before the Screenshare

        TaskScheduler(imp); // Checks bypasses using Task Scheduler

        Prefetch(imp); // Checks executed files with Prefetch

        RecentFiles(imp); // Checks recently accessed files.

        AppCrash(imp); // Checks executed (and crashed) files with WER

        Javaw(); // Checks unlegit clients and mods using Minecraft's memory

        XRay(imp); // Checks xray resource packs

        ImportCode(imp); // Checks bypasses using code imports on system terminals

        UnpluggedDevices(imp); // Checks unplugged devices

        MouseKeys(); // Checks if autoclickers using MouseKeys are enabled.

        MouseCheck(imp); // Checks the VID and PID of the mouse being used.

        VirtualMachine(imp); // Checks if the user is using a Virtual Machine

        csrss(imp); // Checks execution of unsigned files with modified extensions, unsigned executed files and unsigned injected dlls

        USNJournal(imp); // Checks certain file modifications, such as macro modifications, replaced files and special characters

        Macros(); // Checks for macro files modifications. This should run at the end to counter macro switch profile bypasses
*/

namespace Checks {
    class Check {
    public:
        virtual void runCheck(bool imp) = 0;
        virtual ~Check() {}
    };

    class MacroStringsCheck : public Check {
    public:
        void runCheck(bool imp) override {
            MacroStrings(imp);
        }
    };

    class ExecutedFilesCheck : public Check {
    public:
        void runCheck(bool imp) override {
            ExecutedFiles(imp);
        }
    };

    class USNJournalClearedCheck : public Check {
    public:
        void runCheck(bool imp) override {
            USNJournalCleared(imp);
        }
    };

    class SystemTimeChangeCheck : public Check {
    public:
        void runCheck(bool imp) override {
#ifdef _WIN64
            SystemTimeChange(imp);
#endif
        }
    };

    class SystemInformerCheck : public Check {
    public:
        void runCheck(bool imp) override {
            SystemInformer(imp);
        }
    };

    class RestartedProcessesCheck : public Check {
    public:
        void runCheck(bool imp) override {
            RestartedProcesses(imp);
        }
    };

    class EventlogBypassCheck : public Check {
    public:
        void runCheck(bool imp) override {
            EventlogBypass(imp);
        }
    };

    class LocalHostCheck : public Check {
    public:
        void runCheck(bool imp) override {
            LocalHost();
        }
    };

    class BamCheck : public Check {
    public:
        void runCheck(bool imp) override {
            bam(imp);
        }
    };

    class ReplacedDisksCheck : public Check {
    public:
        void runCheck(bool imp) override {
            ReplacedDisks(imp);
        }
    };

    class TaskSchedulerCheck : public Check {
    public:
        void runCheck(bool imp) override {
            TaskScheduler(imp);
        }
    };

    class PrefetchCheck : public Check {
    public:
        void runCheck(bool imp) override {
            Prefetch(imp);
        }
    };

    class RecentFilesCheck : public Check {
    public:
        void runCheck(bool imp) override {
            RecentFiles(imp);
        }
    };

    class AppCrashCheck : public Check {
    public:
        void runCheck(bool imp) override {
            AppCrash(imp);
        }
    };

    class JavawCheck : public Check {
    public:
        void runCheck(bool imp) override {
            Javaw();
        }
    };

    class XRayCheck : public Check {
    public:
        void runCheck(bool imp) override {
            XRay(imp);
        }
    };

    class ImportCodeCheck : public Check {
    public:
        void runCheck(bool imp) override {
            ImportCode(imp);
        }
    };

    class UnpluggedDevicesCheck : public Check {
    public:
        void runCheck(bool imp) override {
            UnpluggedDevices(imp);
        }
    };

    class MouseKeysCheck : public Check {
    public:
        void runCheck(bool imp) override {
            MouseKeys();
        }
    };

    class MiceCheck : public Check {
    public:
        void runCheck(bool imp) override {
            MouseCheck(imp);
        }
    };

    class VirtualMachineCheck : public Check {
    public:
        void runCheck(bool imp) override {
            VirtualMachine(imp);
        }
    };

    class CsrssCheck : public Check {
    public:
        void runCheck(bool imp) override {
            csrss(imp);
        }
    };

    class USNJournalCheck : public Check {
    public:
        void runCheck(bool imp) override {
            USNJournal(imp);
        }
    };

    class MacrosCheck : public Check {
    public:
        void runCheck(bool imp) override {
            Macros();
        }
    };
}