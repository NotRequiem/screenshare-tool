#include "mouse.hpp"

// Initialize COM and connect to WMI
IWbemLocator* pLoc = nullptr;
IWbemServices* pSvc = nullptr;

// Counter for the number of mice found
int mouseCount = 0;

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

static void PrintError(const wchar_t* context, HRESULT hr) {
    _com_error err(hr);
    LPCTSTR errMsg = err.ErrorMessage();
    std::wcerr << context << " Error: 0x" << std::hex << hr << " " << errMsg << std::endl;
}

void MouseCheck(bool imp) {
    // Set console color for informative output
    if (!imp) {
        setConsoleTextColor(BrightGreen);
        std::wcout << "[Device Scanner] Retrieving mice's VID and PID...\n";
        resetConsoleTextColor();
    }

    // Initialize COM for singlethreaded apartment model
    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        PrintError(L"COM Initialization", hr);
        return;
    }

    // Initialize COM security settings
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) { // Ignore RPC_E_TOO_LATE, indicating security settings are already initialized
        PrintError(L"COM Security Initialization", hr);
        CleanupCOM();
        return;
    }

    // Create an instance of the WbemLocator interface
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc));
    if (FAILED(hr)) {
        PrintError(L"WbemLocator Creation", hr);
        CleanupCOM();
        return;
    }

    // Connect to the WMI service on the local machine
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, 0, 0, 0, &pSvc);
    if (FAILED(hr)) {
        PrintError(L"WMI Connection", hr);
        CleanupCOM();
        return;
    }

    // Set security levels on the proxy
    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        PrintError(L"Proxy Blanket Configuration", hr);
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
            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn); // ignore hr warning declarations

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

                    // Increment the mouse count
                    mouseCount++;
                }

                VariantClear(&vtProp);
            }

            pclsObj->Release();
        }

        pEnumerator->Release();

        // Print a warning if two or more mice are found
        if (mouseCount >= 2) { // we warn here because windows may false flag this
            std::wcout << "[!] Check in the Windows configuation > Bluetooth & Devices if more than two mices are plugged. If so, ban the user." << std::endl;
        }

        // Release COM interfaces and uninitialize COM
        CleanupCOM();
    }
}
