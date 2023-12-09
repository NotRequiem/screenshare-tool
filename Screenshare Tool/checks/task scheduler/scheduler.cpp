#include "scheduler.hpp"

namespace fs = std::filesystem;

// Function to check if a file executed with Task Scheduler is valid
static bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

// Function to check if a line contains a file path
static bool containsFilePath(const std::string& line) {
    // Check if "line" contains a letter, followed by a colon, and after that followed by a slash
    size_t colonPos = line.find(':');
    size_t slashPos = line.find('\\', colonPos);
    return colonPos != std::string::npos && slashPos != std::string::npos;
}

// Function to check if a line ends with a backslash
static bool endsWithBackslash(const std::string& line) {
    return line.ends_with("\\");
}

static void DetectTaskScheduler(DWORD pid) {
    // Set to keep track of printed paths
    std::set<std::string> printedPaths;

    // Regular expression pattern to match file paths
    std::regex SchedulerRegex(R"(^\"?[A-Za-z]:\\[^"\r\n]+?\.(dll|exe|bat|jar|vbs)\b)");
    std::wstring commandLine = L"memory.exe -p " + std::to_wstring(pid);

    SECURITY_ATTRIBUTES saAttr{};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hChildStdoutRd, hChildStdoutWr;
    CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0);
    SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    si.hStdOutput = hChildStdoutWr;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hide the console window so that it does not annoy the Screensharer

    PROCESS_INFORMATION pi;

    if (CreateProcessW(NULL, const_cast<wchar_t*>(commandLine.c_str()), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(hChildStdoutWr);

        CHAR buffer[4096]{};
        DWORD bytesRead;

        std::string previousLine;  // To store the previous line

        while (ReadFile(hChildStdoutRd, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead != 0) {
            std::string outputString(buffer, bytesRead);

            // Use istringstream to parse the output into lines
            std::istringstream outputStream(outputString);
            std::string line;

            while (std::getline(outputStream, line)) {
                // Find the first non-space character
                auto firstNonSpace = std::find_if(line.begin(), line.end(), [](unsigned char x) { return !std::isspace(x); });

                // Find the last non-space character
                auto lastNonSpace = std::find_if(line.rbegin(), line.rend(), [](unsigned char x) { return !std::isspace(x); }).base();

                // Erase characters outside the range [firstNonSpace, lastNonSpace)
                line.erase(lastNonSpace, line.end());
                line.erase(line.begin(), firstNonSpace);

                // Define the file extensions to check for in the check for files executed with unicode characters
                std::vector<std::string> fileExtensions = { ".exe", ".dll", ".bat", ".vbs", ".jar", ".ps1", ".py" };

                // Check if the current line contains a file path
                if (containsFilePath(line) && endsWithBackslash(previousLine)) {
                    // Check if the next line contains ONLY one of the strings in the vector
                    if (std::any_of(fileExtensions.begin(), fileExtensions.end(), [&line](const std::string& ext) {
                        return line == ext;
                        })) {
                        // Print a warning message
                        std::cout << "[!] Detected file executed with special characters." << std::endl;
                        // Print the previous line for reference
                        std::cout << "    Line 1: " << previousLine << std::endl;
                        // Print the current line that triggered the warning
                        std::cout << "    Line 2: " << line << std::endl;
                    }
                }

                std::smatch match;
                if (!line.empty() && printedPaths.find(line) == printedPaths.end() && std::regex_search(line, match, SchedulerRegex)) {
                    std::string matchedPart = match.str();

                    // Remove double quotes
                    matchedPart.erase(std::remove(matchedPart.begin(), matchedPart.end(), '\"'), matchedPart.end());

                    if (printedPaths.find(matchedPart) == printedPaths.end()) {
                        
                            if (fs::exists(matchedPart)) {
                                std::wstring lineW;

                                int requiredSize = MultiByteToWideChar(CP_UTF8, 0, matchedPart.c_str(), -1, nullptr, 0);
                                if (requiredSize > 0) {
                                    lineW.resize(static_cast<std::basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t>>::size_type>(requiredSize) - 1);  // Exclude null terminator
                                    MultiByteToWideChar(CP_UTF8, 0, matchedPart.c_str(), -1, &lineW[0], requiredSize);
                                }

                                if (!IsFileSignatureValid(lineW)) {
                                    std::cout << "[#] Executed & Unsigned file: " << matchedPart << std::endl;
                                }
                            }
                            else {
                                std::cout << "[#] Executed & Deleted file: " << matchedPart << std::endl;
                            }

                        printedPaths.insert(matchedPart);
                    }
                }

                previousLine = line;
            }
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hChildStdoutRd);
}

// Function to perform Task Scheduler checks using WMI
void TaskScheduler() {
    setConsoleTextColor(Green);
    std::wcout << "[Task Scheduler Scanner] Running checks to detect executed files with task scheduler in memory... " << std::endl;
    resetConsoleTextColor();

    // Service name for Task Scheduler
    const wchar_t* serviceName = L"Schedule";

    // WMI interfaces
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    VARIANT processId;
    VariantInit(&processId);

    // HRESULT to store WMI operation results
    HRESULT hr;

    // Initialize WMI interfaces
    hr = InitializeWMI(pLoc, pSvc);

    // Execute WMI query to retrieve the process ID
    hr = ExecuteWMIQuery(pSvc, serviceName, processId);
    if (FAILED(hr)) {
        UninitializeWMI(pLoc, pSvc);
        return;
    }

    // Check the variant type and call DetectTaskScheduler if it's an integer
    if (V_VT(&processId) == VT_I4) {
        DetectTaskScheduler(V_I4(&processId));
    }
    else {
        std::wcerr << L"[!] Scheduler process is not running. Ban the user." << std::endl;
    }

    VariantClear(&processId);
    UninitializeWMI(pLoc, pSvc);
}