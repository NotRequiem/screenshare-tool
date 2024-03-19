#include "evtquery.hpp"

// Helper function for converting SYSTEMTIME to FILETIME
static FILETIME SystemTimeToFileTime(const SYSTEMTIME& st) {
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    return ft;
}

// Function to calculate the system boot time
static void BootTime(SYSTEMTIME& lastBootTime) {
    ULONGLONG elapsedTime = GetTickCount64();

    // Get the current local time
    GetLocalTime(&lastBootTime);

    // Calculate the start time by subtracting the elapsed time
    FILETIME ftStartTime = SystemTimeToFileTime(lastBootTime);
    ULARGE_INTEGER startDateTime{};
    startDateTime.HighPart = ftStartTime.dwHighDateTime;
    startDateTime.LowPart = ftStartTime.dwLowDateTime;
    startDateTime.QuadPart -= elapsedTime * 10000;

    // Convert the new time back to SYSTEMTIME
    FILETIME ftNewTime{};
    ftNewTime.dwHighDateTime = startDateTime.HighPart;
    ftNewTime.dwLowDateTime = startDateTime.LowPart;

    FileTimeToSystemTime(&ftNewTime, &lastBootTime);
}

// Function to compare two SYSTEMTIME structures
static int CompareSystemTimes(const SYSTEMTIME& time1, const SYSTEMTIME& time2) {
    FILETIME ft1 = SystemTimeToFileTime(time1);
    FILETIME ft2 = SystemTimeToFileTime(time2);
    return CompareFileTime(&ft1, &ft2);
}

// Function to print the event if the system time was modified
static void PrintEvent(EVT_HANDLE hEvent, SYSTEMTIME& lastBootTime) {
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;

    // Create rendering context
    EVT_HANDLE hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    std::vector<EVT_VARIANT> renderedValues;
    PEVT_VARIANT pRenderedValues = nullptr;

    // Loop to render event values
    while (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount)) {
        DWORD status = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER == status) {
            dwBufferSize = dwBufferUsed;
            renderedValues.resize(dwBufferSize / sizeof(EVT_VARIANT));
            pRenderedValues = renderedValues.data();
        }
        else {
            break;
        }
    }

    FILETIME ft{}, lft;
    SYSTEMTIME st;
    if (pRenderedValues) {
        // Extract system time from rendered event
        ft.dwHighDateTime = (DWORD)(pRenderedValues[EvtSystemTimeCreated].FileTimeVal >> 32);
        ft.dwLowDateTime = (DWORD)pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
        FileTimeToLocalFileTime(&ft, &lft);
        FileTimeToSystemTime(&lft, &st);

        // Check if the system time was modified after last boot
        if (CompareSystemTimes(lastBootTime, st) < 0) {
            wprintf(L"[!] The system time was last modified in: %02d/%02d/%04d %02d:%02d:%02d.\n", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
        }
    }

    if (hContext) EvtClose(hContext);
}

// Function to check for system time change events
void SystemTimeChange(bool imp) {
    if (!imp) {
        setConsoleTextColor(BrightYellow);
        std::wcout << "[Eventlog Scanner] Running checks to detect if the system time was changed...\n";
        resetConsoleTextColor();
    }

    EVT_HANDLE hResults;
    EVT_HANDLE hEvent;
    DWORD dwReturned = 0;

    // Specify the query to retrieve system time change events
    LPCWSTR pwsPath = L"System";
    LPCWSTR pwsQuery = L"*[System[(EventID=22) and Provider[@Name='Microsoft-Windows-Kernel-General']]]";

    // Query the event log
    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);

    // Get the last boot time
    SYSTEMTIME lastBootTime;
    BootTime(lastBootTime);

    // Retrieve the next event
    if (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned)) {
        PrintEvent(hEvent, lastBootTime);
        EvtClose(hEvent);
    }

    // Close the query handle
    EvtClose(hResults);
}
