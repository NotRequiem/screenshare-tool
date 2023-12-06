#include "main.hpp"

int main() {
    if (!IsRunningAsAdmin()) {
    std::cout << "Reopen this screenshare tool as administrator." << std::endl;
    std::cin.get();
    return 1;
    }

    checkMemoryExe(); // Checks if the memory scanner is present

    VirtualMachine(); // Detects if the user is using a Virtual Machine

    // ================================================================================================
    //                                    SCREENSHARE TOOL CHECKS
    // ================================================================================================

    MacroStrings(); // Checks for macro strings (This should run first because macro strings are fastly erased)

    ExecutedFiles(); // Detects executed files using several processes

    MouseCheck(); // Detects if the user has two plugged mouses at the same time (which is bannable due to the possibility of autoclicking)

    USNJournalCleared(); // Check if USNJournal was cleared

    SystemInformer(); // Checks if System Informer or Process Hacker were executed

    RestartedProcesses(); // Checks if certain processes needed to check for certain bypasses and file executions are restarted

    SystemTimeChange(); // Checks if the system time was changed

    EventlogBypass(); // Checks if eventlog was bypassed

    SuspiciousMods(); // Checks for mods that were modified while Minecraft was running

    ReplacedDisks(); // Detects physical or virtual disks replaced or formatted before the Screenshare

    ImportCode(); // Detects bypasses using code imports on system terminals

    TaskScheduler(); // Detects bypasses using Task Scheduler

    UnpluggedDevices(); // Detects unplugged devices

    Macros(); // Checks for macro files modifications

    csrss(); // Detects execution of unsigned files with modified extensions, unsigned executed files and unsigned injected dlls

    USNJournal(); // Detects certain file modifications, such as macro modifications, replaced files and special characters

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
