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

static bool LastLogonTime(SYSTEMTIME& lastLogonTime) {
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    HRESULT hres;

    // Initialize COM with only 1 thread to avoid problems with the service name wmi query
    hres = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hres)) {
        return false;
    }

    hres = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr
    );

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // Obtain the initial locator to WMI
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        reinterpret_cast<LPVOID*>(&pLoc)
    );

    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // Connect to WMI through the IWbemLocator::ConnectServer method
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        nullptr,
        nullptr,
        0,
        0,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE
    );

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }
    
    IEnumWbemClassObject* pEnumerator = nullptr;

    hres = pSvc->ExecQuery(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM Win32_LogonSession WHERE LogonType = 2"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator
    );

    if (FAILED(hres)) {
        return false;
    }

    FILETIME maxLogonFileTime = {};
    bool isFirstLogon = true;

    while (pEnumerator) {
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (uReturn == 0) {
            break;
        }

        VARIANT vtProp;
        VariantInit(&vtProp);

        hres = pclsObj->Get(L"StartTime", 0, &vtProp, 0, 0);

        if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR) {
            SYSTEMTIME logonTime{};
            swscanf_s(vtProp.bstrVal, L"%4hd%2hd%2hd%2hd%2hd%2hd",
                &logonTime.wYear, &logonTime.wMonth, &logonTime.wDay,
                &logonTime.wHour, &logonTime.wMinute, &logonTime.wSecond);

            FILETIME logonFileTime;
            SystemTimeToFileTime(&logonTime, &logonFileTime);

            if (isFirstLogon || CompareFileTime(&logonFileTime, &maxLogonFileTime) > 0) {
                maxLogonFileTime = logonFileTime;
                lastLogonTime = logonTime;
                isFirstLogon = false;
            }
        }

        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pEnumerator->Release();

    if (isFirstLogon) {
        return false;
    }

    CoUninitialize();

    return true;
}

static bool GetProcessCreationTime(DWORD processId, FILETIME& creationTime) {

    EnableDebugPrivilege();

    // Open the process with PROCESS_QUERY_INFORMATION access rights to retrieve the started time
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);

    // Check if the process was successfully opened
    if (hProcess == NULL) {
        return false;
    }

    // Dummy variables to receive process times
    FILETIME dummyCreationTime, dummyExitTime, dummyKernelTime, dummyUserTime;

    // Get process times
    if (GetProcessTimes(hProcess, &dummyCreationTime, &dummyExitTime, &dummyKernelTime, &dummyUserTime)) {
        CloseHandle(hProcess);

        creationTime = dummyCreationTime;

        FILETIME localCreationTime;
        if (FileTimeToLocalFileTime(&creationTime, &localCreationTime)) {   
           return true;
        }
        else {
            return false;
        }
    }
    else {
        CloseHandle(hProcess);
        return false;
    }
}

static bool IsProcessRestartedSinceLastLogon(DWORD processId, const SYSTEMTIME& lastLogonTime) {
    FILETIME creationTime;
    if (GetProcessCreationTime(processId, creationTime)) {
        // Convert lastLogonTime to FILETIME for comparison
        FILETIME lastLogonFileTime;
        SystemTimeToFileTime(&lastLogonTime, &lastLogonFileTime);

        FILETIME localCreationTime;
        FileTimeToLocalFileTime(&creationTime, &localCreationTime);

        // Add 120 seconds to the creation time to avoid weird false flags
        const ULONGLONG secondsToAdd = 120;
        const ULONGLONG intervalPerSecond = 10000000; // 100-nanosecond intervals in a second
        ULONGLONG creationTimeInIntervals = (static_cast<ULONGLONG>(localCreationTime.dwHighDateTime) << 32) | localCreationTime.dwLowDateTime;
        creationTimeInIntervals += secondsToAdd * intervalPerSecond;

        // Check if the adjusted creation time is after the last logon time + 120 seconds
        if (CompareFileTime(&localCreationTime, &lastLogonFileTime) > 0) {
            std::wcout << L"[!] Process with ID " << processId << L" has been restarted since the last logon time. This is bannable." << std::endl;
            return true;
        }
    }

    return false;
}

// Function to check if useful processes are restarted
void RestartedProcesses() {
    setConsoleTextColor(Gray);
    std::wcout << L"[System Scanner] Running checks for restarted processes...\n";
    resetConsoleTextColor();

    EnableDebugPrivilege();

    // Process to check if they were restarted or not
    const wchar_t* serviceNames[] = { L"PlugPlay", L"PcaSvc", L"Schedule", L"Eventlog", L"DiagTrack" };

    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;

    SYSTEMTIME lastLogonTime;
    if (!LastLogonTime(lastLogonTime)) {
        return;
    }

    // Iterate through specified services
    for (const wchar_t* serviceName : serviceNames) {
        VARIANT processId;
        VariantInit(&processId);

        HRESULT hr;

        // Initialize WMI
        hr = InitializeWMI(pLoc, pSvc);
        if (FAILED(hr)) {
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Execute WMI query to get process ID
        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {

            // Check if the process has been restarted since the last logon
            IsProcessRestartedSinceLastLogon(V_I4(&processId), lastLogonTime);
        }
        else {
            // If the service name is not "DiagTrack", print the warning.
            // This is because DiagTrack can be stopped in normal situations.
            if (wcscmp(serviceName, L"DiagTrack") != 0) {
                std::wcerr << L"[!] The following process is not running for service " << serviceName << L": '" << serviceName << L"'. Print a warning message." << std::endl;
            }
        }

        // Clear the Variant, which is used to store data retrieved from WMI queries
        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
    }
}