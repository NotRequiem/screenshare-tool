#include "..\wmi\wmi.hpp"
#include "..\gui\color.hpp"
#include "importcode.hpp"

static void DetectImportCode(DWORD pid) {
    const std::vector<std::pair<std::wstring, std::wstring>> patternsAndMessages = {
        { L"Invoke-RestMethod", L"[!] Found ImportCode string: 'Invoke-RestMethod'." },
        { L"Invoke-Expression", L"[!] Found ImportCode string: 'Invoke-Expression'." },
        { L"import base64", L"[!] Found ImportCode string: 'import base64'." }
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

    STARTUPINFOW si = { sizeof(STARTUPINFO) };
    si.hStdOutput = hChildStdoutWr;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the console window so that it does not annoy the Screensharer

    PROCESS_INFORMATION pi;

    if (CreateProcessW(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(hChildStdoutWr);

        CHAR buffer[4096]{};
        DWORD bytesRead;

        while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
            // Convert wide char buffer to std::wstring
            std::wstring outputWString(buffer, buffer + bytesRead / sizeof(wchar_t));

            for (const auto& patternAndMessage : patternsAndMessages) {
                const auto& searchPattern = patternAndMessage.first;
                const auto& message = patternAndMessage.second;

                // Convert search pattern to std::wstring for comparison
                std::wstring patternWString = std::wstring(searchPattern.begin(), searchPattern.end());

                if (outputWString.find(patternWString) != std::wstring::npos) {
                    std::wcout << message << L"on process with pid: " << pid << L". This is bannable!" << std::endl;
                }
            }
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hChildStdoutRd);
}

// Function to detect Import Code bypasses by checking specific services
void ImportCode() {
    Console::SetColor(ConsoleColor::Red, ConsoleColor::Black);
    std::wcout << "[Code Import Scanner] Running checks to detect Import code bypasses... " << std::endl;
    Console::ResetColor();
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

        // Execute WMI query to get process ID
        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (FAILED(hr)) {
            UninitializeWMI(pLoc, pSvc);
            return;
        }

        // Check if process ID is retrieved successfully
        if (V_VT(&processId) == VT_I4) {
            // Detect Import Code in the specified process
            DetectImportCode(V_I4(&processId));
        }
        else {
            std::wcerr << L"[!] The following process is not running: '" << serviceName << L"'. Ban the user." << std::endl;
        }

        // Clear the variant and uninitialize WMI
        VariantClear(&processId);
        UninitializeWMI(pLoc, pSvc);
    }
}