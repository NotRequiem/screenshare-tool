#include "main.hpp"

int main() {
    if (!IsRunningAsAdmin()) {
    std::cout << "Reopen this screenshare tool as administrator." << std::endl;
    std::cin.get();
    return 1;
    }

    checkMemoryExe(); // Checks if the memory scanner is present

    setConsoleTextColor(Magenta);
    std::wcout << "[Virtual Machine Scanner] Running checks to detect virtual machines...\n";
    resetConsoleTextColor();

    VirtualMachine(); // Detects if the user is using a Virtual Machine

    setlocale(LC_ALL, "");  // Set the locale for wide character support

    // ================================================================================================
    //                                    SCREENSHARE TOOL CHECKS
    // ================================================================================================
    
    std::wcout << "DO NOT CLICK INSIDE THE CONSOLE DURING THE SCAN!\n";

    MacroStrings(); // Checks for macro strings. This should run first because macro strings are fastly erased

    ExecutedFiles(); // Detects executed files using several processes

    UnpluggedDevices(); // Detects unplugged devices

    MouseCheck(); // Detects the VID and PID of the user

    MouseKeys(); // Checks if autoclickers using MouseKeys are enabled.

    USNJournalCleared(); // Check if USNJournal was cleared

    SystemInformer(); // Checks if System Informer or Process Hacker were executed

    RestartedProcesses(); // Checks if certain processes needed to check for certain bypasses and file executions are restarted

    EventlogBypass(); // Checks if eventlog was bypassed

    SystemTimeChange(); // Checks if the system time was changed

    LocalHost(); // Checks if there is a networh shared drive that could contain cheat files

    bam(); // Checks executed files with the Background Activity Moderator

    SuspiciousMods(); // Checks for mods that were modified while Minecraft was running

    ReplacedDisks(); // Detects physical or virtual disks replaced or formatted before the Screenshare

    ImportCode(); // Detects bypasses using code imports on system terminals

    TaskScheduler(); // Detects bypasses using Task Scheduler

    Javaw(); // Detects unlegit clients and mods using Minecraft's memory

    Prefetch(); // Detects executed files with Prefetch

    csrss(); // Detects execution of unsigned files with modified extensions, unsigned executed files and unsigned injected dlls

    USNJournal(); // Detects certain file modifications, such as macro modifications, replaced files and special characters

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
