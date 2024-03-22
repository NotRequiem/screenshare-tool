#include "main.hpp"

namespace Checks {
    class Check {
    public:
        virtual void runCheck(bool imp) = 0;
        virtual ~Check() {}
    };

    class MacroStringsCheck : public Check {
    public:
        void runCheck(bool imp) override {
            std::cout << "Running Macro Strings Check." << std::endl;

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

    class SuspiciousModsCheck : public Check {
    public:
        void runCheck(bool imp) override {
            SuspiciousMods();

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

int main(int argc, char* argv[]) {
    // ================================================================================================
    //                                    SCREENSHARE TOOL INITIALIZATION
    // ================================================================================================

    using namespace Checks;

    // Set the locale for wide character support
    if (setlocale(LC_ALL, ".UTF-8") == nullptr) {
        std::cerr << "Failed to set UTF-8 locale." << std::endl;
    }

    CheckProcessorArchitecture();
    checkMemoryExe(); // Checks if the memory scanner is present

    std::vector<std::shared_ptr<Check>> checks = []() {
        return std::vector<std::shared_ptr<Check>> {
            std::make_shared<MacroStringsCheck>(),
                std::make_shared<ExecutedFilesCheck>(),
                std::make_shared<USNJournalClearedCheck>(),
                std::make_shared<SystemTimeChangeCheck>(),
                std::make_shared<SystemInformerCheck>(),
                std::make_shared<RestartedProcessesCheck>(),
                std::make_shared<EventlogBypassCheck>(),
                std::make_shared<LocalHostCheck>(),
                std::make_shared<BamCheck>(),
                std::make_shared<SuspiciousModsCheck>(),
                std::make_shared<ReplacedDisksCheck>(),
                std::make_shared<TaskSchedulerCheck>(),
                std::make_shared<PrefetchCheck>(),
                std::make_shared<RecentFilesCheck>(),
                std::make_shared<AppCrashCheck>(),
                std::make_shared<JavawCheck>(),
                std::make_shared<XRayCheck>(),
                std::make_shared<ImportCodeCheck>(),
                std::make_shared<UnpluggedDevicesCheck>(),
                std::make_shared<MouseKeysCheck>(),
                std::make_shared<MiceCheck>(),
                std::make_shared<VirtualMachineCheck>(),
                std::make_shared<CsrssCheck>(),
                std::make_shared<USNJournalCheck>(),
                std::make_shared<MacrosCheck>()
        };
        }();

        auto findImpFlag = [&argc, &argv]() {
            return std::find_if(argv, argv + argc, [](const char* arg) {
                return std::strcmp(arg, "-i") == 0 || std::strcmp(arg, "-I") == 0;
                }) != argv + argc; // Return true if -i or -I is found, false otherwise
            };

        bool imp = findImpFlag(); // Get the boolean value from findImpFlag()

        for (const auto& check : checks) {
            check->runCheck(imp); // Pass the boolean value to runCheck
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

        // ------------------------------------------------------------------------------------------------
        //                                  ONBOARD MEMORY MACROS CHECKS
        // ------------------------------------------------------------------------------------------------

        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        if (!CreateProcess(NULL,   // Module name (NULL to use the same module as the calling process)
            NULL,                   // Command line (NULL to indicate no command line arguments)
            NULL,                   // Process handle not inheritable
            NULL,                   // Thread handle not inheritable
            FALSE,                  // Set handle inheritance to FALSE
            CREATE_NEW_CONSOLE,     // Create a new console window for the new process
            NULL,                   // Use parent's environment block
            NULL,                   // Use parent's starting directory 
            &si,                    // Pointer to STARTUPINFO structure
            &pi))                   // Pointer to PROCESS_INFORMATION structure
        {
            // If the process creation fails, fallback to AllocConsole
            if (AllocConsole()) {
                FILE* pCout, * pCerr;
                if (freopen_s(&pCout, "CONOUT$", "w", stdout) != 0) {
                    MessageBox(NULL, "Failed to redirect stdout", "Error", MB_OK | MB_ICONERROR);
                    return 1;
                }
                if (freopen_s(&pCerr, "CONOUT$", "w", stderr) != 0) {
                    MessageBox(NULL, "Failed to redirect stderr", "Error", MB_OK | MB_ICONERROR);
                    return 1;
                }

                // Execute hook code
                ExecuteHookCode();

                // Free the console
                FreeConsole();
            }
            else {
                // If AllocConsole also fails, execute the hook code without a console
                ExecuteHookCode();
            }
        }
        else {
            // Execute the hook code within the new process
            ExecuteHookCode();

            // Close process and thread handles
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        return 0;
}
