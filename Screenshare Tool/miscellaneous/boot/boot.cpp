#include "boot.hpp"

static bool LogonBoot(SYSTEMTIME& lastLogonTime) {
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

        // Use the previously assigned hres
        if (SUCCEEDED(hres)) {
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
        }

        VariantClear(&vtProp);
        pclsObj->Release();
    }

    if (pEnumerator) {
        pEnumerator->Release();
    }

    if (isFirstLogon) {
        return false;
    }

    CoUninitialize();

    return true;
}