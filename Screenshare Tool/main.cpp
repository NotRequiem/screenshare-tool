#include "main.hpp"

int main(int argc, char* argv[]) {
    // ================================================================================================
    //                                    SCREENSHARE TOOL INITIALIZATION
    // ================================================================================================
      
    // Check command line arguments to know if the ss tool should print important information
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-I") == 0) {
            imp = true;
        }
    }

    checkMemoryExe(); // Checks if the memory scanner is present
    setlocale(LC_ALL, "");  // Set the locale for wide character support

    // ================================================================================================
    //                                    SCREENSHARE TOOL CHECKS
    // ================================================================================================

    MacroStrings(imp); // Checks for macro strings. This should run first because macro strings are fastly erased

    ExecutedFiles(imp); // Checks executed files using several processes

    USNJournalCleared(imp); // Check if USNJournal was cleared

#ifdef _WIN64
    SystemTimeChange(imp); // Checks if the system time was changed
#endif

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
