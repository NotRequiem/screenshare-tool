#include <iostream>
#include <vector>
#include <tuple>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <codecvt>

bool warningDisplayed = false;

static void scanProcessStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex, const std::wstring& message) {
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry)) {
        do {
            if (wcscmp(entry.szExeFile, processName) == 0) {
                DWORD pid = entry.th32ProcessID;

                // Build command line directly in the scanProcessStrings function
                std::wstring commandLine = L"memory scanner.exe -p " + std::to_wstring(pid);

                SECURITY_ATTRIBUTES saAttr;
                saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
                saAttr.bInheritHandle = TRUE;
                saAttr.lpSecurityDescriptor = NULL;

                HANDLE hChildStdoutRd, hChildStdoutWr;
                CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
                SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

                STARTUPINFO si = { sizeof(STARTUPINFO) };
                si.hStdOutput = hChildStdoutWr;
                si.dwFlags |= STARTF_USESTDHANDLES;

                PROCESS_INFORMATION pi;

                if (CreateProcess(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                    CloseHandle(hChildStdoutWr);

                    CHAR buffer[4096]{};
                    DWORD bytesRead;

                    while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
                        // Convert std::wstring to std::string
                        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
                        std::string searchPatternStr = converter.to_bytes(searchPattern);

                        // Check if the search pattern is found in the output
                        std::string outputString(buffer, bytesRead);
                        if (outputString.find(searchPatternStr) != std::string::npos) {
                            std::wcout << message << searchPattern << L". This is bannable" << std::endl;
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

int main() {
    std::vector<std::tuple<const wchar_t*, std::wstring, bool, std::wstring>> processParameters = {
        std::make_tuple(L"lghub_agent.exe", L"durationms", true, L"Found illegal macro string in lghub_agent.exe: "),
        std::make_tuple(L"Razer Synapse.exe", L"DeleteMacroEvent", false, L"Found illegal macro string in Razer Synapse.exe: "),
        std::make_tuple(L"Razer Synapse 3.exe", L"SetKeysPerSecond", false, L"Found illegal macro string in Razer Synapse 3.exe: "),
        std::make_tuple(L"RazerCentralService.exe", L"Datasync: Status: COMPLETE Action: NONE Macros/", false, L"Found illegal macro string in RazerCentralService.exe: "),
        std::make_tuple(L"SteelSeriesGGClient.exe", L"delay.+is_deleted", true, L"Found illegal macro string in SteelSeriesGGClient.exe: "),
        std::make_tuple(L"Onikuma.exe", L"LeftKey CODE:", false, L"Found illegal macro string inOnikuma.exe: "),
    };

    for (const auto& params : processParameters) {
        const wchar_t* processName = std::get<0>(params);
        std::wstring searchPattern = std::get<1>(params);
        bool useRegex = std::get<2>(params);
        std::wstring message = std::get<3>(params);

        std::wcout << L"Scanning process: " << processName << std::endl;

        scanProcessStrings(processName, searchPattern, useRegex, message);
    }

    return 0;
}
