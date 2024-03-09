#include "wmi.hpp"

/**
 * @brief Initializes COM and sets up security for WMI operations.
 *
 * This function initializes COM, sets up security settings, and creates an instance
 * of the WbemLocator interface. It then connects to the "ROOT\\CIMV2" namespace and
 * obtains the IWbemServices interface for WMI operations.
 *
 * @param[out] pLoc - Pointer to the IWbemLocator interface.
 * @param[out] pSvc - Pointer to the IWbemServices interface.
 * @return HRESULT - Indicates success or failure of the initialization.
 */

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
        reinterpret_cast<LPVOID*>(&pLoc)
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

/**
 * @brief Releases resources and uninitializes COM after WMI operations.
 *
 * This function releases the IWbemServices and IWbemLocator interfaces,
 * and uninitializes COM after WMI operations.
 *
 * @param[in] pLoc - Pointer to the IWbemLocator interface.
 * @param[in] pSvc - Pointer to the IWbemServices interface.
 */

void UninitializeWMI(IWbemLocator* pLoc, IWbemServices* pSvc) {
    if (pSvc) {
        pSvc->Release();
    }

    if (pLoc) {
        pLoc->Release();
    }

    CoUninitialize();
}

/**
 * @brief Executes a WMI query to retrieve information about a Windows service.
 *
 * This function executes a WMI query to retrieve information about a Windows service,
 * specified by its service name. The query looks for services in the "Win32_Service" class
 * with a matching name and retrieves the associated process ID.
 *
 * @param[in] pSvc - Pointer to the IWbemServices interface.
 * @param[in] serviceName - The name of the Windows service to query.
 * @param[out] processId - The process ID of the specified service.
 * @return HRESULT - Indicates success or failure of the WMI query.
 */

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