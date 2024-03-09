#include "main.hpp"

int main(int argc, char* argv[]) {
    bool imp = false;

    // Check command line arguments to know if the ss tool should print important information
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-I") == 0) {
            imp = true;
        }
    }

    checkMemoryExe(); // Checks if the memory scanner is present
    if (!imp) {
        setConsoleTextColor(BrightWhite);
        std::wcout << "[Virtual Machine Scanner] Running checks to detect virtual machines...\n";
        resetConsoleTextColor();
    }
    
    VirtualMachine(); // Detects if the user is using a Virtual Machine

    setlocale(LC_ALL, "");  // Set the locale for wide character support

    // ================================================================================================
    //                                    SCREENSHARE TOOL CHECKS
    // ================================================================================================
    
    std::wcout << "DO NOT CLICK INSIDE THE CONSOLE DURING THE SCAN!\n";
    std::wcout << "If you press Enter, the console will continue but will skip the current check.\n";

    MacroStrings(imp); // Checks for macro strings. This should run first because macro strings are fastly erased

    ExecutedFiles(imp); // Detects executed files using several processes

    UnpluggedDevices(imp); // Detects unplugged devices

    MouseCheck(imp); // Detects the VID and PID of the user

    MouseKeys(); // Checks if autoclickers using MouseKeys are enabled.

    USNJournalCleared(imp); // Check if USNJournal was cleared

    SystemTimeChange(imp); // Checks if the system time was changed

    SystemInformer(imp); // Checks if System Informer or Process Hacker were executed

    RestartedProcesses(imp); // Checks if certain processes needed to check for certain bypasses and file executions are restarted

    EventlogBypass(imp); // Checks if eventlog was bypassed

    LocalHost(); // Checks if there is a networh shared drive that could contain cheat files

    bam(imp); // Checks executed files with the Background Activity Moderator

    SuspiciousMods(); // Checks for mods that were modified while Minecraft was running

    ReplacedDisks(imp); // Detects physical or virtual disks replaced or formatted before the Screenshare

    ImportCode(imp); // Detects bypasses using code imports on system terminals

    TaskScheduler(imp); // Detects bypasses using Task Scheduler

    Prefetch(imp); // Detects executed files with Prefetch

    RecentFiles(imp); // Detects recently accessed files.

    AppCrash(imp); // Detects executed (and crashed) files with WER

    Javaw(); // Detects unlegit clients and mods using Minecraft's memory

    csrss(imp); // Detects execution of unsigned files with modified extensions, unsigned executed files and unsigned injected dlls

    USNJournal(imp); // Detects certain file modifications, such as macro modifications, replaced files and special characters

    XRay(imp); // Detects xray resource packs

    Macros(); // Checks for macro files modifications. This should run at the end to counter macro switch profile bypasses

    // ------------------------------------------------------------------------------------------------
    //                                  ONBOARD MEMORY MACROS CHECKS
    // ------------------------------------------------------------------------------------------------

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

    return 0;
}
