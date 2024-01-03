#include "evtquery.hpp"

// Helper function for converting SYSTEMTIME to FILETIME
static FILETIME SystemTimeToFileTime(const SYSTEMTIME& st) {
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    return ft;
}

static void BootTime(SYSTEMTIME& lastBootTime) {
    ULONGLONG elapsedTime = GetTickCount64();

    GetLocalTime(&lastBootTime);

    FILETIME ftStartTime = SystemTimeToFileTime(lastBootTime);
    ULARGE_INTEGER startDateTime = *reinterpret_cast<ULARGE_INTEGER*>(&ftStartTime);
    startDateTime.QuadPart -= elapsedTime * 10000;

    FileTimeToSystemTime(reinterpret_cast<FILETIME*>(&startDateTime), &lastBootTime);
}

static int CompareSystemTimes(const SYSTEMTIME& time1, const SYSTEMTIME& time2) {
    FILETIME ft1 = SystemTimeToFileTime(time1);
    FILETIME ft2 = SystemTimeToFileTime(time2);
    return CompareFileTime(&ft1, &ft2);
}

static void PrintEvent(EVT_HANDLE hEvent, SYSTEMTIME& lastBootTime) {
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;

    EVT_HANDLE hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);

    std::vector<EVT_VARIANT> renderedValues;
    PEVT_VARIANT pRenderedValues = nullptr;

    while (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount)) {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError())) {
            dwBufferSize = dwBufferUsed;
            renderedValues.resize(dwBufferSize / sizeof(EVT_VARIANT));
            pRenderedValues = renderedValues.data();
        }
        else {
            EvtClose(hContext);
            return;
        }
    }

    FILETIME ft{}, lft;
    SYSTEMTIME st;

    if (pRenderedValues) {
        ft.dwHighDateTime = (DWORD)(pRenderedValues[EvtSystemTimeCreated].FileTimeVal >> 32);
        ft.dwLowDateTime = (DWORD)pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
        FileTimeToLocalFileTime(&ft, &lft);
        FileTimeToSystemTime(&lft, &st);

        if (CompareSystemTimes(lastBootTime, st) < 0) {
            wprintf(L"[!] The system time was last modified in: %02d/%02d/%04d %02d:%02d:%02d.\n", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);
        }

        // No need to free pRenderedValues with smart pointers
    }

    if (hContext) EvtClose(hContext);
}

void SystemTimeChange() {
    setConsoleTextColor(BrightYellow);
    std::wcout << "[Eventlog Scanner] Running checks to detect if the system time was changed...\n";
    resetConsoleTextColor();

    EVT_HANDLE hResults;
    EVT_HANDLE hEvent;
    DWORD dwReturned = 0;

    LPCWSTR pwsPath = L"System";
    LPCWSTR pwsQuery = L"*[System[(EventID=22) and Provider[@Name='Microsoft-Windows-Kernel-General']]]";

    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);

    SYSTEMTIME lastBootTime;
    BootTime(lastBootTime);

    if (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned)) {
        PrintEvent(hEvent, lastBootTime);
        EvtClose(hEvent);
    }

    EvtClose(hResults);
}
