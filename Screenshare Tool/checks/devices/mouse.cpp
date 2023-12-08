#include "mouse.hpp"

// Initialize COM and connect to WMI
IWbemLocator* pLoc = nullptr;
IWbemServices* pSvc = nullptr;

static void CleanupCOM() {
    if (pSvc) {
        pSvc->Release();
        pSvc = nullptr;
    }
    if (pLoc) {
        pLoc->Release();
        pLoc = nullptr;
    }
    CoUninitialize();
}

void MouseCheck() {
    // Set console color for informative output
    setConsoleTextColor(BrightGreen);
    std::wcout << "[Device Scanner] Retrieving mice's VID and PID..." << std::endl;
    resetConsoleTextColor();

    // Initialize COM for multithreaded apartment model
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        std::wcerr << "Failed to initialize COM" << std::endl;
        return;
    }

    // Initialize COM security settings
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr)) {
        std::wcerr << "Failed to initialize COM security" << std::endl;
        CleanupCOM();
        return;
    }

    // Create an instance of the WbemLocator interface
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc));
    if (FAILED(hr)) {
        std::wcerr << "Failed to create WbemLocator instance" << std::endl;
        CleanupCOM();
        return;
    }

    // Connect to the WMI service on the local machine
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, 0, 0, 0, &pSvc);
    if (FAILED(hr)) {
        std::wcerr << "Failed to connect to WMI service" << std::endl;
        CleanupCOM();
        return;
    }

    // Set security levels on the proxy
    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        std::wcerr << "Failed to set proxy blanket" << std::endl;
        CleanupCOM();
        return;
    }

    // Execute a WMI query to retrieve information about devices with "Mouse" in their caption
    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_PnPEntity WHERE Caption LIKE '%Mouse%'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &pEnumerator);

    if (SUCCEEDED(hr)) {
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        // Loop through the query results
        while (pEnumerator) {
            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (uReturn == 0) {
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);

            // Retrieve the DeviceID property from the WMI object
            hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr)) {
                // Parse VID and PID from DeviceID
                // The format is usually something like "USB\\VID_XXXX&PID_XXXX"
                // Extract the values of VID and PID based on the format
                // For example, VID_046D&PID_C077 (in my case)
                std::wstring deviceID = vtProp.bstrVal;
                size_t vidPos = deviceID.find(L"VID_");
                size_t pidPos = deviceID.find(L"PID_");

                if (vidPos != std::wstring::npos && pidPos != std::wstring::npos) {
                    std::wcout << L"[#] VID : " << deviceID.substr(vidPos + 4, 4) << std::endl;
                    std::wcout << L"[#] PID : " << deviceID.substr(pidPos + 4, 4) << std::endl;
                }

                VariantClear(&vtProp);
            }

            pclsObj->Release();
        }

        pEnumerator->Release();
    }

    // Release COM interfaces and uninitialize COM
    CleanupCOM();
}
