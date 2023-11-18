#include "main.hpp"

int main() {
    if (!IsRunningAsAdmin()) {
        std::cout << "Reopen this screenshare tool as administrator." << std::endl;
        return 1;
    }

    EnableDebugPrivilege(); // Enable privileges to scan certain processes like Scheduler.

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
            std::wcout << serviceName << L" Scanning strings on process: " << processId.intVal << std::endl;

            scanServiceStrings(serviceName, std::get<1>(params), std::get<2>(params));

            VariantClear(&processId);
        } else {
            std::wcout << L"WMI query for " << serviceName << L" failed with error: " << hr << std::endl;
        }
    }

    UninitializeWMI(pLoc, pSvc);

    // ------------------------------------------------------------------------------------------------
    // USN JOURNAL CHECKS
    // ------------------------------------------------------------------------------------------------

    std::vector<std::wstring> driveLetters = GetDriveLetters();

    for (const std::wstring& driveLetter : driveLetters) {
        CheckDriveJournal(driveLetter);
    }

    fsutil(); // Parses USNJournal to detect certain file modifications //

    // ------------------------------------------------------------------------------------------------
    // FILE MACRO CHECKS
    // ------------------------------------------------------------------------------------------------

    wchar_t username[MAX_PATH];
    DWORD usernameSize = MAX_PATH;
    if (GetUserNameW(username, &usernameSize)) {
        CheckRecentFileModifications();
    }

    // ------------------------------------------------------------------------------------------------
    // JAVAW MODIFICATION CHECKS
    // ------------------------------------------------------------------------------------------------

    SYSTEMTIME sysTime;
    GetProcessStartTime(_T("javaw.exe"), &sysTime);
    GetProcessStartTime(_T("Minecraft.Windows.exe"), &sysTime);

    // ------------------------------------------------------------------------------------------------
    // VIRTUAL MACHINE CHECKS
    // ------------------------------------------------------------------------------------------------

    if (VM::detect()) {
        std::cout << "Virtual machine detected. It can be used to send mouse events between physical and virtual machines in order to autoclick." << std::endl;
    }
    else {
        std::cout << "This user is not using a Virtual Machine" << std::endl;
    }

    // ------------------------------------------------------------------------------------------------
    // OTHER CHECKS
    // ------------------------------------------------------------------------------------------------

    CheckDiskInstallation(); // Detects physical or virtual disks replaced or formatted //
    ImportCodeDetector::RunImportCodeChecks(); // Detects code imports on system terminals //
    RunTaskSchedulerChecks();
    CsrssCheck::csrss(); // Detects execution of unsigned files with modified extensions, unsigned executed files and unsigned injected dlls //

    printf("All checks have finished succesfully. Running final checks...\n");

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
