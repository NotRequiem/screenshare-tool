#include "..\wmi\wmi.hpp"
#include "..\gui\color.hpp"
#include "prochandler.hpp"

// Enables Debug privileges to get the started time of the certain processes
static void EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp{};

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
                
    CloseHandle(hToken);
}

static void BootTime(SYSTEMTIME& startTime) {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

    // Calculate elapsed time in seconds, minutes, and hours
    DWORD seconds = (DWORD)(elapsedTime / 1000) % 60;
    DWORD minutes = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000) * 60)) % 60);
    DWORD hours = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000 * 60) * 60)) % 24);

    // Get the current local time
    GetLocalTime(&startTime);

    // Calculate the time when the computer started
    FILETIME ftStartTime;
    SystemTimeToFileTime(&startTime, &ftStartTime);
    ULARGE_INTEGER startDateTime = *(ULARGE_INTEGER*)&ftStartTime;
    startDateTime.QuadPart -= elapsedTime * 10000; // Convert elapsed time to 100-nanosecond intervals

    // Convert the calculated start time back to SYSTEMTIME
    FileTimeToSystemTime((FILETIME*)&startDateTime, &startTime);
}

bool GetProcessCreationTime(DWORD processId, FILETIME& creationTime) {
    // Open the process with PROCESS_QUERY_INFORMATION access rights
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);

    // Check if the process was successfully opened
    if (hProcess == NULL) {
        return false;
    }

    // Dummy variables to receive process times
    FILETIME dummyCreationTime, dummyExitTime, dummyKernelTime, dummyUserTime;

    // Get process times
    if (GetProcessTimes(hProcess, &dummyCreationTime, &dummyExitTime, &dummyKernelTime, &dummyUserTime)) {
        // Close the process handle
        CloseHandle(hProcess);

        // Set the creation time and return true
        creationTime = dummyCreationTime;
        return true;
    } else {
        // Close the process handle before returning false
        CloseHandle(hProcess);
        return false;
    }
}

static bool IsProcessRestartedSinceBoot(DWORD processId, const SYSTEMTIME& bootTime) {
    FILETIME creationTime;
    if (GetProcessCreationTime(processId, creationTime)) {
        SYSTEMTIME sysTime;
        if (FileTimeToSystemTime(&creationTime, &sysTime)) {

            // Convert bootTime to FILETIME for CompareFileTime
            FILETIME bootFileTime;
            SystemTimeToFileTime(&bootTime, &bootFileTime);

            // Add a small buffer (1-2 seconds) to the boot time for comparison
            ULARGE_INTEGER bootDateTime = *(ULARGE_INTEGER*)&bootFileTime;
            bootDateTime.QuadPart += static_cast<unsigned long long>(10) * 10000000;  // Add 2 seconds in 100-nanosecond intervals
            bootFileTime = *(FILETIME*)&bootDateTime;

            // Check if the process creation time is greater than the adjusted system boot time
            int comparisonResult = CompareFileTime(&creationTime, &bootFileTime);

            if (comparisonResult > 0) {
                std::wcout << L"[!] Process with ID " << processId << L" has been restarted since the last boot. Ban the user." << std::endl;
                return true;
            }
        }
    }

    return false;
}


void RestartedProcesses() {
    Console::SetColor(ConsoleColor::Gray, ConsoleColor::Black);
    std::wcout << L"[System Scanner] Checking for restarted processes..." << std::endl;
    Console::ResetColor();

    EnableDebugPrivilege();

    // Process to check if they were restarted or not
    const wchar_t* serviceNames[] = { L"PlugPlay", L"PcaSvc", L"Schedule", L"Eventlog", L"DiagTrack"};

    SYSTEMTIME bootTime;
    BootTime(bootTime);

    // Iterate through specified services
    for (const wchar_t* serviceName : serviceNames) {
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        VARIANT processId;
        VariantInit(&processId);

        HRESULT hr;

        // Initialize WMI
        hr = InitializeWMI(pLoc, pSvc);

        // Execute WMI query to get process ID
        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {
            // Check if the process has been restarted since the last boot
            IsProcessRestartedSinceBoot(V_I4(&processId), bootTime);
        }
        else {
            std::wcerr << L"[!] The following process is not running: '" << serviceName << L"'. Ban the user." << std::endl;
        }

        // Clear the variant and uninitialize WMI
        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
    }
}