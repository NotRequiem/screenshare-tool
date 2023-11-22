#include "main.hpp"

int main() {
    if (!IsRunningAsAdmin()) {
    std::cout << "Reopen this screenshare tool as administrator." << std::endl;
    std::cin.get();
    return 1;
    }

    // ================================================================================================
    //                                    SCREENSHARE TOOL CHECKS
    // ================================================================================================

    MacroStrings(); // Checks for macro strings (This should run first because macro strings are fastly erased)

    ExecutedFiles(); // Detects executed jar and bat files

    MouseCheck(); // Detects if the user has two plugged mouses at the same time (which is bannable due to the possibility of autoclicking)

    VirtualMachine(); // Detects if the user is using a Virtual Machine

    USNJournal(); // Detects certain file modifications, such as macro modifications, replaced files and special characters

    USNJournalCleared(); // Check if USNJournal was cleared

    SuspiciousMods(); // Checks for mods that were modified while Minecraft was running

    ReplacedDisks(); // Detects physical or virtual disks replaced or formatted before the Screenshare
    
    ImportCode(); // Detects bypasses using code imports on system terminals

    TaskScheduler(); // Detects bypasses using Task Scheduler

    UnpluggedDevices(); // Detects unplugged devices

    Macros(); // Checks for macro files modifications

    csrss(); // Detects execution of unsigned files with modified extensions, unsigned executed files and unsigned injected dlls

    // ------------------------------------------------------------------------------------------------
    // ONBOARD MEMORY MACROS CHECKS
    // ------------------------------------------------------------------------------------------------

    if (InstallMouseHook() && InstallKeyboardHook()) {
        printf("Running onboard memory macro checks...\n");
        printf("Press the DELETE key to stop the checks for onboard macros at any time.\n");

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
