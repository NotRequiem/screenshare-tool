#include "..\gui\color.hpp"
#include "evtquery.hpp"

static void BootTime(SYSTEMTIME& lastBootTime) {
    // Get the tick count (milliseconds) since the system was started
    ULONGLONG elapsedTime = GetTickCount64();

    // Calculate elapsed time in seconds, minutes, and hours
    DWORD seconds = (DWORD)(elapsedTime / 1000) % 60;
    DWORD minutes = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000) * 60)) % 60);
    DWORD hours = (DWORD)((elapsedTime / (static_cast<unsigned long long>(1000 * 60) * 60)) % 24);

    // Get the current local time
    GetLocalTime(&lastBootTime);

    // Calculate the time when the computer started
    FILETIME ftStartTime;
    SystemTimeToFileTime(&lastBootTime, &ftStartTime);
    ULARGE_INTEGER startDateTime = *(ULARGE_INTEGER*)&ftStartTime;
    startDateTime.QuadPart -= elapsedTime * 10000; // Convert elapsed time to 100-nanosecond intervals

    // Convert the calculated start time back to SYSTEMTIME
    FileTimeToSystemTime((FILETIME*)&startDateTime, &lastBootTime);
}

// Function to compare two SYSTEMTIME structures
static int CompareSystemTimes(const SYSTEMTIME& time1, const SYSTEMTIME& time2) {
    FILETIME ft1, ft2;
    SystemTimeToFileTime(&time1, &ft1);
    SystemTimeToFileTime(&time2, &ft2);
    return CompareFileTime(&ft1, &ft2);
}

// Function to print event details and check for system time changes
static void PrintEvent(EVT_HANDLE hEvent, SYSTEMTIME& lastBootTime) {
    // Variables for rendering event values
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;

    // Create an event rendering context
    EVT_HANDLE hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);

    // Render the event values
    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount)) {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError())) {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if (pRenderedValues) {
                if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount)) {
                    free(pRenderedValues);
                    EvtClose(hContext);
                    return;
                }
            } else {
                EvtClose(hContext);
                return;
            }
        } else {
            EvtClose(hContext);
            return;
        }
    }

    FILETIME ft{}, lft;
    SYSTEMTIME st;

    if (pRenderedValues) {
        // Extract system time from the event values
        ft.dwHighDateTime = (DWORD)(pRenderedValues[EvtSystemTimeCreated].FileTimeVal >> 32);
        ft.dwLowDateTime = (DWORD)pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
        FileTimeToLocalFileTime(&ft, &lft);
        FileTimeToSystemTime(&lft, &st);

        // Compare the last boot time with the system time change to know if we should print a warning message or not
        if (CompareSystemTimes(lastBootTime, st) < 0) {
            wprintf(L"[!] Warning: System time change detected after last boot time. This may false flag and cannot be fixed.\n");
            wprintf(L"[#] The system time was last modified in: %02d/%02d/%04d %02d:%02d:%02d\n", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
        }

        free(pRenderedValues);
    }

    // Close the rendering context
    if (hContext) EvtClose(hContext);
}

// Function to check for system time changes in event logs
void SystemTimeChange() {
    // Set console color for information display
    Console::SetColor(ConsoleColor::Gray, ConsoleColor::Black);
    std::wcout << "[System Scanner] Running checks to detect if the system time was changed... " << std::endl;
    Console::ResetColor();

    // Query event logs for events related to system time changes
    EVT_HANDLE hResults;
    EVT_HANDLE hEvent;
    DWORD dwReturned = 0;

    // Define the event log query parameters
    LPCWSTR pwsPath = L"System";
    LPCWSTR pwsQuery = L"*[System[(EventID=22) and Provider[@Name='Microsoft-Windows-Kernel-General']]]";

    // Create an event log query and retrieve the results
    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);

    // Get the system's last boot time
    SYSTEMTIME lastBootTime;
    BootTime(lastBootTime);

    // Process the first event in the query results
    if (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned)) {
        // Print event details and check for system time changes
        PrintEvent(hEvent, lastBootTime);
        EvtClose(hEvent);
    }

    // Close the event log query results
    EvtClose(hResults);
}
