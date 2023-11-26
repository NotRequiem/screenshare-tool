#include "..\wmi\wmi.hpp"
#include "..\digital signature\trustverify.hpp"
#include "..\gui\color.hpp"
#include "scheduler.hpp"

// Function to check if a file executed with Task Scheduler is valid
static bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

static void printFilteredStrings(const std::string& filename) {
    std::ifstream inputFile(filename);
    std::set<std::string> printedPaths;

    std::regex pattern(R"(^[A-Za-z]:\\.+\.(dll|exe|bat|jar)|"[A-Za-z]:\\.+\.(dll|exe|bat|jar))");
    std::smatch matches;
    std::string line;

    while (std::getline(inputFile, line)) {
        if (std::regex_search(line, matches, pattern)) {
            std::string matchedPath = matches[0].str();

            if (!matchedPath.empty() && matchedPath.front() == '"') {
                matchedPath.erase(matchedPath.begin());
            }
            if (!matchedPath.empty() && matchedPath.back() == '"') {
                matchedPath.erase(matchedPath.end() - 1);
            }

            if (printedPaths.find(matchedPath) != printedPaths.end()) {
                continue;
            }
            printedPaths.insert(matchedPath);

            std::wstring widePath(matchedPath.begin(), matchedPath.end());
            if (!IsFileSignatureValid(widePath)) {
                std::cout << "Suspicious file executed with task scheduler: " << matchedPath << std::endl;
            }
        }
    }

    inputFile.close();

    // Remove the text file after finishing the process
    std::remove(filename.c_str());
}

static void DetectTaskScheduler(DWORD pid) {
    std::wstring command = L"memory.exe -p " + std::to_wstring(pid) + L" > process_strings.txt";

    // Convert the wide string to a wide character array (LPCWSTR)
    LPCWSTR wideCommand = command.c_str();

    printFilteredStrings("process_strings.txt");
}

// Function to perform Task Scheduler checks using WMI
void TaskScheduler() {
    Console::SetColor(ConsoleColor::Green, ConsoleColor::Black);
    std::wcout << "[Task Scheduler Scanner] Running checks to detect executed files with task scheduler in memory... " << std::endl;
    Console::ResetColor();

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
    if (FAILED(hr)) {
        std::wcerr << L"WMI initialization failed for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
        return;
    }

    // Execute WMI query to retrieve the process ID
    hr = ExecuteWMIQuery(pSvc, serviceName, processId);
    if (FAILED(hr)) {
        std::wcerr << L"WMI query execution failed for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses. Error code: 0x" << std::hex << hr << std::dec << std::endl;
        // Uninitialize WMI interfaces in case of failure
        UninitializeWMI(pLoc, pSvc);
        return;
    }

    // Check the variant type and call DetectTaskScheduler if it's an integer
    if (V_VT(&processId) == VT_I4) {
        DetectTaskScheduler(V_I4(&processId));
    }
    else {
        std::wcerr << L"Failed to retrieve Process ID for service '" << serviceName << L"' while trying to detect Task Scheduler bypasses." << std::endl;
    }

    VariantClear(&processId);
    UninitializeWMI(pLoc, pSvc);
}