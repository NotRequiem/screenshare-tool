#include "macroscanner.hpp"

// Function to scan specified process strings for specific patterns and display detection messages.
static void scanProcessStrings(const wchar_t* processName, const std::wstring& searchPattern, bool useRegex, const std::wstring& message) {
    // Initialize PROCESSENTRY32 structure for process enumeration
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    // Create a snapshot of the system's process information
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // Iterate through the processes to find the specified one
    if (Process32First(snapshot, &entry)) {
        do {
            // Check if the current process matches the specified name
            if (strcmp(entry.szExeFile, reinterpret_cast<const char*>(processName)) == 0) {
                DWORD pid = entry.th32ProcessID;

                // Build command line to execute the memory scanner.exe
                std::wstring commandLine = L"memory.exe -p " + std::to_wstring(pid);

                // Set up security attributes for the pipe
                SECURITY_ATTRIBUTES saAttr{};
                saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
                saAttr.bInheritHandle = TRUE;
                saAttr.lpSecurityDescriptor = NULL;

                // Create a pipe for the child process's stdout
                HANDLE hChildStdoutRd, hChildStdoutWr;
                CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
                SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

                // Set up startup info for the child process
                STARTUPINFOW si = { sizeof(STARTUPINFO) };
                si.hStdOutput = hChildStdoutWr;
                si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;  // Hide the console window to avoid interruption

                // Initialize PROCESS_INFORMATION structure to receive information about the spawned process
                PROCESS_INFORMATION pi;

                // Create the child process
                if (CreateProcessW(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
                    // Close the write end of the pipe as it is not needed in this process
                    CloseHandle(hChildStdoutWr);

                    // Buffer to store output from the child process
                    CHAR buffer[4096]{};
                    DWORD bytesRead;

                    // Read output from the pipe and search for specified patterns
                    while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
                        // Convert std::wstring to std::string for proper parsing
                        int requiredSize = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(buffer), -1, NULL, 0, NULL, NULL);
                        std::string outputString(requiredSize, 0);
                        WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(buffer), -1, &outputString[0], requiredSize, NULL, NULL);
                        outputString.resize(strlen(outputString.c_str())); // Remove null terminator added by WideCharToMultiByte

                        // Check if regex matching is specified (true/false in the tuple)
                        if (useRegex) {
                            // Use regex to match the macro pattern if specified in the tuple
                            std::regex regexPattern(outputString.c_str());
                            if (std::regex_search(outputString, regexPattern)) {
                                std::wcout << message << searchPattern << L". This is bannable." << std::endl;
                            }
                        } else {
                            // Use normal string finding
                            int patternSize = WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(searchPattern.c_str()), -1, NULL, 0, NULL, NULL);
                            std::string narrowSearchPattern(patternSize, 0);
                            WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<LPCWCH>(searchPattern.c_str()), -1, &narrowSearchPattern[0], patternSize, NULL, NULL);
                            narrowSearchPattern.resize(strlen(narrowSearchPattern.c_str()));

                            if (outputString.find(narrowSearchPattern) != std::string::npos) {
                                std::wcout << message << searchPattern << L". This is bannable." << std::endl;
                            }
                        }
                    }

                    // Wait for the child process to finish
                    WaitForSingleObject(pi.hProcess, INFINITE);

                    // Close handles to avoid resource leaks
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }

                // Close the read end of the pipe
                CloseHandle(hChildStdoutRd);

                // Break out of the loop since the process is found
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }

    // Close the snapshot handle
    CloseHandle(snapshot);
}

// Function to check for specific macro strings in various processes
void MacroStrings() {
    // Set console color for information display
    setConsoleTextColor(BrightBlue);
    std::wcout << "[Macro Scanner] Running checks for deleted macro traces in memory...\n";
    resetConsoleTextColor();

    // Define parameters for finding macro traces using process scanning
    std::vector<std::tuple<const wchar_t*, std::wstring, bool, std::wstring>> processParameters = {
        std::make_tuple(L"lghub_agent.exe", L"durationms.+\"isDown\"", true, L"Found macro string in lghub_agent.exe: "),
        std::make_tuple(L"Razer Synapse.exe", L"DeleteMacroEvent", false, L"Found macro string in Razer Synapse.exe: "),
        std::make_tuple(L"Razer Synapse 3.exe", L"SetKeysPerSecond", false, L"Found macro string in Razer Synapse 3.exe: "),
        std::make_tuple(L"RazerCentralService.exe", L"Datasync: Status: COMPLETE Action: NONE Macros/", false, L"Found macro string in RazerCentralService.exe: "),
        std::make_tuple(L"SteelSeriesGGClient.exe", L"delay.+is_deleted", true, L"Found macro string in SteelSeriesGGClient.exe: "),
        std::make_tuple(L"Onikuma.exe", L"LeftKey CODE:", false, L"Found macro string in Onikuma.exe: "),
    };

    // Iterate through each set of parameters and scan the corresponding process
    for (const auto& params : processParameters) {
        const wchar_t* processName = std::get<0>(params);
        std::wstring searchPattern = std::get<1>(params);
        bool useRegex = std::get<2>(params);
        std::wstring message = std::get<3>(params);

        // Call the function to scan the specified process for the given macro trace
        scanProcessStrings(processName, searchPattern, useRegex, message);
    }
}

