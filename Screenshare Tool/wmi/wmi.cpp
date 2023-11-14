#include "wmiserv.hpp"
#include <string>

HRESULT InitializeWMI(IWbemLocator*& pLoc, IWbemServices*& pSvc) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        return hr;
    }

    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hr)) {
        CoUninitialize();
        return hr;
    }

    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc
    );

    if (FAILED(hr)) {
        CoUninitialize();
        return hr;
    }

    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        0,
        NULL,
        NULL,
        &pSvc
    );

    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return hr;
    }

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return hr;
    }

    return S_OK;
}

void UninitializeWMI(IWbemLocator* pLoc, IWbemServices* pSvc) {
    if (pSvc) {
        pSvc->Release();
    }

    if (pLoc) {
        pLoc->Release();
    }

    CoUninitialize();
}

HRESULT ExecuteWMIQuery(IWbemServices* pSvc, const wchar_t* serviceName, VARIANT& processId) {
    std::wstring query = L"SELECT * FROM Win32_Service WHERE Name='" + std::wstring(serviceName) + L"'";

    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        return hr;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (SUCCEEDED(hr) && uReturn > 0) {
        hr = pclsObj->Get(L"ProcessId", 0, &processId, 0, 0);
        pclsObj->Release();
    }

    pEnumerator->Release();
    return hr;
}
