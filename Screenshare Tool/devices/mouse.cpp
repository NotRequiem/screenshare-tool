#include "..\gui\color.hpp"
#include "mouse.hpp"

void MouseCheck() {
    Console::SetColor(ConsoleColor::BrightGreen, ConsoleColor::Black);
    std::wcout << "[Device Scanner] Retrieving mice's VID and PID..." << std::endl;
    Console::ResetColor();

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);

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
        CoUninitialize();
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
        pLocator->Release();
        CoUninitialize();
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
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
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
        pServices->Release();
        pLocator->Release();
        CoUninitialize();
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
            wprintf(L"User's mouse VID and PID: %s\n", vtProp.bstrVal);
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
}
