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

static int CompareSystemTimes(const SYSTEMTIME& time1, const SYSTEMTIME& time2) {
    FILETIME ft1, ft2;
    SystemTimeToFileTime(&time1, &ft1);
    SystemTimeToFileTime(&time2, &ft2);
    return CompareFileTime(&ft1, &ft2);
}

static void PrintEvent(EVT_HANDLE hEvent, SYSTEMTIME& lastBootTime) {
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;

    EVT_HANDLE hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if (hContext == NULL)
    {
        wprintf(L"EvtCreateRenderContext failed with %lu while detecting system time change modifications.\n", GetLastError());
        return;
    }

    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if (pRenderedValues)
            {
                if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount))
                {
                    wprintf(L"EvtRender failed with %lu while detecting system time change modifications.\n", GetLastError());
                    free(pRenderedValues);
                    EvtClose(hContext);
                    return;
                }
            }
            else
            {
                EvtClose(hContext);
                return;
            }
        }
        else
        {
            wprintf(L"EvtRender failed with %lu while detecting system time change modifications.\n", status);
            EvtClose(hContext);
            return;
        }
    }

    FILETIME ft{}, lft;
    SYSTEMTIME st;

    if (pRenderedValues)
    {
        ft.dwHighDateTime = (DWORD)(pRenderedValues[EvtSystemTimeCreated].FileTimeVal >> 32);
        ft.dwLowDateTime = (DWORD)pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
        FileTimeToLocalFileTime(&ft, &lft);
        FileTimeToSystemTime(&lft, &st);
        wprintf(L"The system time was last modified in: %02d/%02d/%04d %02d:%02d:%02d\n", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);

        // Compare the last boot time with the system time change
        if (CompareSystemTimes(lastBootTime, st) < 0) {
            wprintf(L"[!] Warning: System time change detected after last boot time. This can be used to bypass macro file modifications. Ban the user!\n");
        }

        free(pRenderedValues);
    }

    if (hContext) EvtClose(hContext);
}

void SystemTimeChange() {
    Console::SetColor(ConsoleColor::Gray, ConsoleColor::Black);
    std::wcout << "[System Scanner] Running checks to detect if the system time was changed... " << std::endl;
    Console::ResetColor();
    EVT_HANDLE hResults;
    EVT_HANDLE hEvent;
    DWORD dwReturned = 0;

    LPCWSTR pwsPath = L"System";
    LPCWSTR pwsQuery = L"*[System[(EventID=24) and Provider[@Name='Microsoft-Windows-Kernel-General']]]";

    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (NULL == hResults)
    {
        wprintf(L"EvtQuery failed with %lu while detecting system time change modifications.\n", GetLastError());
    }
    else
    {
        SYSTEMTIME lastBootTime;
        BootTime(lastBootTime);

        if (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned))
        {
            PrintEvent(hEvent, lastBootTime);
            EvtClose(hEvent);
        }
        else
        {
            wprintf(L"EvtNext failed while detecting system time change modifications.\n");
        }

        EvtClose(hResults);
    }
}
