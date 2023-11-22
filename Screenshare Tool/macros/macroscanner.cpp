#include "macroscanner.hpp"

bool warningDisplayed = false;

static void scanProcessStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex, const std::wstring& message) {
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry)) {
        do {
            if (wcscmp(entry.szExeFile, processName) == 0) {
                DWORD pid = entry.th32ProcessID;

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

                        if (useRegex) {
                            // Use regex to match the search pattern if specified in the tuple
                            std::regex regexPattern(converter.to_bytes(searchPattern));
                            if (std::regex_search(outputString, regexPattern)) {
                                std::wcout << message << searchPattern << L". This is bannable" << std::endl;
                            }
                        }
                        else {
                            // Use normal string finding
                            if (outputString.find(converter.to_bytes(searchPattern)) != std::string::npos) {
                                std::wcout << message << searchPattern << L". This is bannable!" << std::endl;
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

                break;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

static void MacroStrings() {
    std::vector<std::tuple<const wchar_t*, std::wstring, bool, std::wstring>> processParameters = {
        std::make_tuple(L"lghub_agent.exe", L"durationms.+\"isDown\"", true, L"Found macro string in lghub_agent.exe: "),
        std::make_tuple(L"Razer Synapse.exe", L"DeleteMacroEvent", false, L"Found macro string in Razer Synapse.exe: "),
        std::make_tuple(L"Razer Synapse 3.exe", L"SetKeysPerSecond", false, L"Found macro string in Razer Synapse 3.exe: "),
        std::make_tuple(L"RazerCentralService.exe", L"Datasync: Status: COMPLETE Action: NONE Macros/", false, L"Found macro string in RazerCentralService.exe: "),
        std::make_tuple(L"SteelSeriesGGClient.exe", L"delay.+is_deleted", true, L"Found macro string in SteelSeriesGGClient.exe: "),
        std::make_tuple(L"Onikuma.exe", L"LeftKey CODE:", false, L"Found macro string in Onikuma.exe: "),
    };

    for (const auto& params : processParameters) {
        const wchar_t* processName = std::get<0>(params);
        std::wstring searchPattern = std::get<1>(params);
        bool useRegex = std::get<2>(params);
        std::wstring message = std::get<3>(params);

        scanProcessStrings(processName, searchPattern, useRegex, message);
    }

}
