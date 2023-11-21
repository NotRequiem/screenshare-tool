#include "mouse.hpp"

bool MouseCheck() {
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::cerr << "Failed to initialize COM library." << std::endl;
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
        std::cerr << "Failed to initialize security." << std::endl;
        CoUninitialize();
        return hr;
    }

    IWbemLocator* pLocator = NULL;
    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLocator
    );

    if (FAILED(hr)) {
        std::cerr << "Failed to create IWbemLocator object." << std::endl;
        CoUninitialize();
        return hr;
    }

    IWbemServices* pServices = NULL;
    hr = pLocator->ConnectServer(
        SysAllocString(L"ROOT\\CIMv2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pServices
    );

    if (FAILED(hr)) {
        std::cerr << "Failed to connect to WMI." << std::endl;
        pLocator->Release();
        CoUninitialize();
        return hr;
    }

    hr = CoSetProxyBlanket(
        pServices,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr)) {
        std::cerr << "Failed to set proxy blanket." << std::endl;
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return hr;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pServices->ExecQuery(
        SysAllocString(L"WQL"),
        SysAllocString(L"SELECT * FROM Win32_PointingDevice"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hr)) {
        std::cerr << "Failed to execute WMI query." << std::endl;
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
        return hr;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    int deviceCount = 0;

    while (pEnumerator) {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (uReturn == 0) {
            break;
        }

        VARIANT vtProp;
        VariantInit(&vtProp);

        hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            wprintf(L"Mouse: %s\n", vtProp.bstrVal);
            VariantClear(&vtProp);
        }

        wprintf(L"\n");

        pclsObj->Release();
        deviceCount++;
    }

    pEnumerator->Release();
    pServices->Release();
    pLocator->Release();
    CoUninitialize();

    // Display warning if there are more than one pointing devices
    if (deviceCount > 1) {
        std::cerr << "WARNING: This user has two mice connected on this computer, which is bannable." << std::endl;
    }

    return 0;
}

int main() {
    MouseCheck();

    return 0;
}
