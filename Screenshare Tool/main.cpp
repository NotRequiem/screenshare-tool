#include "main.hpp"

int main() {
    if (!IsRunningAsAdmin()) {
    std::cout << "Reopen this screenshare tool as administrator." << std::endl;
    std::cin.get();
    return 1;
    }

    EnableDebugPrivilege(); // Enable privileges to scan certain processes system processes.

    Macros(); // Checks for macros (This should run first because macro strings are fastly erased)

    // ------------------------------------------------------------------------------------------------
    // CUSTOM PROCESS STRING SCANNER
    // ------------------------------------------------------------------------------------------------

    /** Define custom strings to search in processes
     * 
     * First parameter: Process name
     * Second parameter: String to search
     * Third parameter: If the scanner should filter the string as a regular expression (true) or not (false)
     * 
    */

    std::vector<std::tuple<const wchar_t*, std::wstring, bool>> processParameters = {
        std::make_tuple(L"lghub_agent.exe", L"durationms.+\"isDown\"", true),
        std::make_tuple(L"Razer Synapse.exe", L"DeleteMacroEvent", false),
        std::make_tuple(L"Razer Synapse 3.exe", L"SetKeysPerSecond", false),
        std::make_tuple(L"RazerCentralService.exe", L"Datasync: Status: COMPLETE Action: NONE Macros/", false),
        std::make_tuple(L"SteelSeriesGGClient.exe", L"delay.+is_deleted", true),
        std::make_tuple(L"Onikuma.exe", L"LeftKey CODE:", false),
        std::make_tuple(L"explorer.exe", L"file:///.+?(.bat|.vbs)", true)
    };

    for (const auto& params : processParameters) {
        const wchar_t* processName = std::get<0>(params);
        std::wstring searchPattern = std::get<1>(params);
        bool useRegex = std::get<2>(params);

        scanProcessStrings(processName, searchPattern, useRegex);
    }

    // ------------------------------------------------------------------------------------------------
    // CUSTOM SERVICE STRING SCANNER (USE THIS IF YOU NEED TO SCAN STRINGS IN SVCHOST.EXE PROCESSES)
    // ------------------------------------------------------------------------------------------------

    HRESULT hr;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    hr = InitializeWMI(pLoc, pSvc);
    if (FAILED(hr)) {
        std::cerr << "WMI initialization failed with error: " << hr << std::endl;
        return 1;
    }

    /** Define custom strings to search in processes
     * 
     * First parameter: Service name
     * Second parameter: String to search
     * Third parameter: If the scanner should filter the string as a regular expression (true) or not (false)
     * 
    */

    std::vector<std::tuple<const wchar_t*, std::wstring, bool>> serviceParameters = {
        std::make_tuple(L"PlugPlay", L"jar", false),
        std::make_tuple(L"PcaSvc", L".bat", false),
    };

    for (const auto& params : serviceParameters) {
        const wchar_t* serviceName = std::get<0>(params);
        VARIANT processId;
        VariantInit(&processId);

        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (SUCCEEDED(hr)) {
            scanServiceStrings(serviceName, std::get<1>(params), std::get<2>(params));

            VariantClear(&processId);
        } else {
            std::wcout << L"WMI query for " << serviceName << L" failed with error: " << hr << std::endl;
        }
    }

    UninitializeWMI(pLoc, pSvc);

    // ================================================================================================
    // SCREENSHARE TOOL CHECKS
    // ================================================================================================

    MouseCheck(); // Detects if the user has two plugged mouses at the same time (which is bannable due to the possibility of autoclicking)

    VirtualMachine(); // Detects if the user is using a Virtual Machine

    USNJournal(); // Detects certain file modifications, such as macro modifications, replaced files and special characters

    USNJournalCleared(); // Check if USNJournal was cleared

    SuspiciousMods(); // Checks for mods that were modified while Minecraft was running

    ReplacedDisks(); // Detects physical or virtual disks replaced or formatted before the Screenshare
    
    ImportCode(); // Detects bypasses using code imports on system terminals

    TaskScheduler(); // Detects bypasses using Task Scheduler

    UnpluggedDevices(); // Detects unplugged devices

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
