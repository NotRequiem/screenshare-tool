#include "main.hpp"

int main() {
    if (!IsRunningAsAdmin()) {
    std::cout << "Reopen this screenshare tool as administrator." << std::endl;
    std::cin.get();
    return 1;
    }

    checkMemoryExe(); // Checks if the memory scanner is present

    Console::SetColor(ConsoleColor::Blue, ConsoleColor::Black);
    std::wcout << "[Virtual Machine Scanner] Running checks for virtual machine detection... " << std::endl;
    Console::ResetColor();
    VirtualMachine(); // Detects if the user is using a Virtual Machine

    // ================================================================================================
    //                                    SCREENSHARE TOOL CHECKS
    // ================================================================================================

    MacroStrings(); // Checks for macro strings (This should run first because macro strings are fastly erased)

    ExecutedFiles(); // Detects executed files using several processes

    MouseCheck(); // Detects if the user has two plugged mouses at the same time (which is bannable due to the possibility of autoclicking)

    USNJournalCleared(); // Check if USNJournal was cleared

    SuspiciousMods(); // Checks for mods that were modified while Minecraft was running

    ReplacedDisks(); // Detects physical or virtual disks replaced or formatted before the Screenshare
    
    ImportCode(); // Detects bypasses using code imports on system terminals

    TaskScheduler(); // Detects bypasses using Task Scheduler

    UnpluggedDevices(); // Detects unplugged devices

    Macros(); // Checks for macro files modifications

    USNJournal(); // Detects certain file modifications, such as macro modifications, replaced files and special characters

    csrss(); // Detects execution of unsigned files with modified extensions, unsigned executed files and unsigned injected dlls

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
