#include "wmiserv.hpp"
#include "importcode.hpp"

bool ImportCodeDetector::isStringChar(unsigned char ch) {
    return (ch >= 32 && ch <= 126);
}

void ImportCodeDetector::DetectImportCode(DWORD pid) {
    if (pid != 0) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess != NULL) {
            SYSTEM_INFO systemInfo;
            GetSystemInfo(&systemInfo);

            unsigned char* address = static_cast<unsigned char*>(systemInfo.lpMinimumApplicationAddress);

            while (address < systemInfo.lpMaximumApplicationAddress) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && !(mbi.Protect & PAGE_GUARD)) {
                        unsigned char buffer[4096];
                        SIZE_T bytesRead;

                        if (ReadProcessMemory(hProcess, address, buffer, sizeof(buffer), &bytesRead)) {
                            std::wstring currentString;
                            for (size_t i = 0; i < bytesRead; i++) {
                                if (isStringChar(buffer[i])) {
                                    wchar_t wideChar;
                                    MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<char*>(&buffer[i]), 1, &wideChar, 1);
                                    currentString += wideChar;
                                }
                                else {
                                    if (!currentString.empty()) {
                                        if (currentString.find(L"Invoke-Expression") != std::wstring::npos ||
                                            currentString.find(L"Invoke-RestMethod") != std::wstring::npos ||
                                            currentString.find(L"https://") != std::wstring::npos ||
                                            currentString.find(L"import base64") != std::wstring::npos){
                                            std::wcout << L"Found possible string related to ImportCode: " << currentString << std::endl;
                                        }
                                        currentString.clear();
                                    }
                                }
                            }
                        }
                    }

                    address += mbi.RegionSize;
                }
                else {
                    break;
                }
            }

            CloseHandle(hProcess);
        }
    }
}

DWORD ImportCodeDetector::GetPIDForClipboardUserService() {
    const wchar_t* serviceDisplayName = L"Clipboard User Service";

    DWORD processId = 0;

    HRESULT hres;

    // Step 1: Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize COM library while trying to detect the ClipboardSvcGroup process.. Error code: " << hres << std::endl;
        return 0;
    }

    // Step 2: Set general COM security levels
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // Let COM choose the default authentication service.
        NULL,                        // Use the currently logged-on user to set the security.
        NULL,                        // Let COM choose the default authentication service.
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Use the default authentication settings for the computer.
        RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonate at the Identify level.
        NULL,                        // Enable the default principles.
        EOAC_NONE,                   // Activate free-threaded mode.
        NULL                         // Pass NULL to use the default setting.
    );

    if (FAILED(hres)) {
        std::wcerr << L"Failed to initialize security while trying to detect the ClipboardSvcGroup process.. Error code: " << hres << std::endl;
        CoUninitialize();
        return 0;
    }

    // Step 3: Obtain the initial locator to WMI
    IWbemLocator* pLoc = nullptr;

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<LPVOID*>(&pLoc));

    if (FAILED(hres)) {
        std::wcerr << L"Failed to create IWbemLocator object while trying to detect the ClipboardSvcGroup process.. Error code: " << hres << std::endl;
        CoUninitialize();
        return 0;
    }

    // Step 4: Connect to WMI through the IWbemLocator::ConnectServer method
    IWbemServices* pSvc = nullptr;

    // Convert namespace to BSTR
    _bstr_t bstrNamespace(L"ROOT\\CIMV2");

    // Connect to the root\cimv2 namespace with the current user and obtain pointer pSvc
    hres = pLoc->ConnectServer(
        bstrNamespace,  // Object path of WMI namespace
        NULL,           // User name
        NULL,           // User password
        0,              // Locale
        NULL,           // Security flags
        0,              // Authority
        0,              // Context object pointer
        &pSvc           // Pointer to IWbemServices proxy
    );

    if (FAILED(hres)) {
        std::wcerr << L"Could not connect to WMI to detect the PID of the ClipboardSvcGroup process. Error code: " << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 0;
    }

    // Step 5: Set security levels on the proxy
    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities
    );

    if (FAILED(hres)) {
        std::wcerr << L"Could not set proxy blanket while trying to detect the ClipboardSvcGroup process. Error code: " << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 0;
    }

    // Step 6: Use the IWbemServices pointer to make requests of WMI
    IEnumWbemClassObject* pEnumerator = nullptr;

    // Convert query to BSTR
    // Use the LIKE operator to match services with a specific display name pattern, i use "LIKE" because clipboardsvcgroup is weird
    _bstr_t bstrQuery(L"SELECT * FROM Win32_Service WHERE DisplayName LIKE '");
    bstrQuery += serviceDisplayName;
    bstrQuery += L"%'";

    // Query services with the specified display name pattern
    hres = pSvc->ExecQuery(
        SysAllocString(L"WQL"),
        SysAllocString(bstrQuery),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );

    if (FAILED(hres)) {
        std::wcerr << L"Query for services failed while trying to detect the ClipboardSvcGroup process. Error code: " << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 0;
    }

    ULONG uReturn = 0;
    IWbemClassObject* pclsObj = nullptr;

    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (uReturn == 0 || FAILED(hres)) {
            break;  // Exit the loop if there are no more items or an error occurs
        }

        VARIANT vtProp;
        VariantInit(&vtProp);  // Initialize vtProp to a safe default value

        // Get the value of the "ProcessId" property
        hres = pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres)) {
            processId = vtProp.uintVal;
            VariantClear(&vtProp);

        }
        else {
            std::wcerr << L"Failed to get ProcessId property when querying ClibpoardSvcGroup. Error code: " << hres << std::endl;
        }

        pclsObj->Release();
    }

    // Cleanup
    // SysFreeString(bstrQuery);  // let _bstr_t handle the memory
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return processId;
}

void ImportCodeDetector::RunImportCodeChecks() {
    const wchar_t* serviceNames[] = { L"diagtrack", L"eventlog" };

    // Adjust token privileges to enable debugging
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        CloseHandle(hToken);
    }

    // Run ImportCode checks for specified services
    for (const wchar_t* serviceName : serviceNames) {
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        VARIANT processId;
        VariantInit(&processId);

        HRESULT hr;

        hr = InitializeWMI(pLoc, pSvc);
        if (FAILED(hr)) {
            std::cerr << "WMI initialization failed for service '" << serviceName << "' while trying to detect ImportCode bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            return;
        }

        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            std::cerr << "WMI query execution failed for service '" << serviceName << "' while trying to detect ImportCode bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        if (V_VT(&processId) == VT_I4) {
            DetectImportCode(V_I4(&processId));
        }
        else {
            std::cerr << "Failed to retrieve Process ID for service '" << serviceName << "' while trying to detect ImportCode bypasses." << std::endl;
        }

        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
    }

    // Run ImportCode checks for Clipboard User Service
    DWORD processId = GetPIDForClipboardUserService();

    if (processId != 0) {
        DetectImportCode(processId);
    }
}

int main() {
    ImportCodeDetector::RunImportCodeChecks();

    return 0;
}