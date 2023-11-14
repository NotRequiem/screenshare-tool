#include "driverchk.hpp"

bool IsDriverRunning(const wchar_t* driverName)
{
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL)
    {
        std::wcout << L"Failed to open service manager: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, driverName, SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        std::wcout << L"Failed to open service: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS status;
    if (!QueryServiceStatus(hService, &status))
    {
        std::wcout << L"Failed to query service status: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    bool running = (status.dwCurrentState == SERVICE_RUNNING);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return running;
}
