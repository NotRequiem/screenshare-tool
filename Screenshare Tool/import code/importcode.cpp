#include "..\wmi\wmi.hpp"
#include "importcode.hpp"

bool warningDisplayed = false;

static void DetectImportCode(DWORD pid) {
    const std::vector<std::pair<std::wstring, std::wstring>> patternsAndMessages = {
        { L"Invoke-RestMethod", L"Found ImportCode string: 'Invoke-RestMethod' " },
        { L"Invoke-Expression", L"Found ImportCode string: 'Invoke-Expression' " },
        { L"import base64", L"Found ImportCode string: 'import base64' " }
    };

    // Build command line to execute the memory scanner.exe
    std::wstring commandLine = L"memory scanner.exe -p " + std::to_wstring(pid);

    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hChildStdoutRd, hChildStdoutWr;
    CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
    SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    si.hStdOutput = hChildStdoutWr;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the console window so that it does not annoy the Screensharer

    PROCESS_INFORMATION pi;

    if (CreateProcess(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(hChildStdoutWr);

        CHAR buffer[4096]{};
        DWORD bytesRead;

        while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
            // Convert std::wstring to std::string for proper parsing
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            std::string outputString(buffer, bytesRead);

            for (const auto& patternAndMessage : patternsAndMessages) {
                const auto& searchPattern = patternAndMessage.first;
                const auto& message = patternAndMessage.second;

                if (outputString.find(converter.to_bytes(searchPattern)) != std::string::npos) {
                    std::wcout << message << L"on process with pid: " << pid << L". This is bannable!" << std::endl;
                }
            }
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        if (!warningDisplayed) {
            std::wcerr << L"Warning: memory scanner.exe not found near the Screenshare Tool. Please download it at: https://github.com/NotRequiem/StrngExtract/blob/main/Release/xxstrings.exe" << std::endl;
            warningDisplayed = true;
        }
    }

    CloseHandle(hChildStdoutRd);
}

// Function to detect Import Code bypasses by checking specific services
void ImportCode() {
    const wchar_t* serviceNames[] = { L"diagtrack", L"eventlog" };

    // Iterate through specified services
    for (const wchar_t* serviceName : serviceNames) {
        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;
        VARIANT processId;
        VariantInit(&processId);

        HRESULT hr;

        // Initialize WMI
        hr = InitializeWMI(pLoc, pSvc);
        if (FAILED(hr)) {
            std::wcerr << L"WMI initialization failed for service '" << serviceName << L"' while trying to detect ImportCode bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            return;
        }

        // Execute WMI query to get process ID
        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            std::wcerr << L"WMI query execution failed for service '" << serviceName << L"' while trying to detect ImportCode bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {
            // Detect Import Code in the specified process
            DetectImportCode(V_I4(&processId));
        }
        else {
            std::wcerr << L"Failed to retrieve Process ID for service '" << serviceName << L"' while trying to detect ImportCode bypasses." << std::endl;
        }

        // Clear the variant and uninitialize WMI
        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
    }
}