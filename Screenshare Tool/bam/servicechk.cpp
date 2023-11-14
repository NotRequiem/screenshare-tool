#include <windows.h>
#include <iostream>
#include "servicechk.hpp"

bool IsServiceRunning(const wchar_t* wideServiceName)
{
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL)
    {
        std::cout << "Failed to open service manager: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, wideServiceName, SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        std::cout << "Failed to open service: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS_PROCESS status;
    DWORD dwBytesNeeded;
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded))
    {
        std::cout << "Failed to query service status: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    bool running = (status.dwCurrentState == SERVICE_RUNNING);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return running;
}
