#include "..\wmi\wmi.hpp"
#include "..\digital signature\trustverify.hpp"
#include "scheduler.hpp"

// Function to check if a file executed with Task Scheduler is valid
bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

void printFilteredStrings(const std::string& filename) {
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
            if (IsFileSignatureValid(widePath)) {
                std::cout << matchedPath << " is signed" << std::endl;
            }
            else {
                std::cout << matchedPath << " is NOT signed" << std::endl;
            }
        }
    }

    inputFile.close();
}

void DetectTaskScheduler(DWORD pid) {
    std::string command = "memory scanner.exe -f -s -pid " + std::to_string(pid) + " > process_strings.txt";
    system(command.c_str());

    printFilteredStrings("process_strings.txt");
}


HANDLE OpenVolume() {
    return CreateFile(TEXT("\\\\.\\c:"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

USN_JOURNAL_DATA QueryJournal(HANDLE hVol) {
    USN_JOURNAL_DATA JournalData = { 0 };
    DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &JournalData, sizeof(JournalData), NULL, NULL);
    return JournalData;
}

DWORDLONG GetFRNForTasksDirectory(HANDLE hVol) {
    std::cout << "Checking deleted tasks by parsing USNJournal in: 'C:\\Windows\\System32\\Tasks'\n";
    HANDLE hDir = CreateFileW(
        L"C:\\Windows\\System32\\Tasks",
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    FILE_ID_INFO fileInfo = {};
    GetFileInformationByHandleEx(hDir, FileIdInfo, &fileInfo, sizeof(fileInfo));
    CloseHandle(hDir);

    DWORDLONG frn;
    memcpy(&frn, &fileInfo.FileId, sizeof(DWORDLONG));
    return frn;
}

void CheckDeletedTasksInUSNJournal(HANDLE hVol, const USN_JOURNAL_DATA& journal) {
    READ_USN_JOURNAL_DATA_V0 ReadData = { 0, 0xFFFFFFFF, FALSE, 0, 0 };
    ReadData.UsnJournalID = journal.UsnJournalID;
    CHAR Buffer[65536];
    DWORD dwBytes, dwRetBytes;
    std::time_t thresholdTime = std::time(nullptr) - 30 * 24 * 60 * 60;
    DWORDLONG tasksFRN = GetFRNForTasksDirectory(hVol);

    int counter = 0;
    const int MAX_ITERATIONS = 1000;

    while (DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL, &ReadData, sizeof(ReadData), &Buffer, sizeof(Buffer), &dwBytes, NULL) && counter < MAX_ITERATIONS) {
        dwRetBytes = dwBytes - sizeof(USN);
        PUSN_RECORD UsnRecord = (PUSN_RECORD)(((PUCHAR)Buffer) + sizeof(USN));

        while (dwRetBytes > 0) {
            if ((UsnRecord->Reason & USN_REASON_FILE_DELETE) && UsnRecord->ParentFileReferenceNumber == tasksFRN) {
                std::time_t timeStamp = static_cast<std::time_t>((static_cast<unsigned long long>(UsnRecord->TimeStamp.QuadPart) - 116444736000000000ULL) / 10000000ULL);
                if (timeStamp > thresholdTime) {
                    struct tm newtime;
                    localtime_s(&newtime, &timeStamp);
                    char buffer[26];
                    asctime_s(buffer, sizeof(buffer), &newtime);
                    std::wcout << L"Deleted task found: " << UsnRecord->FileName << L" at " << buffer;
                }
            }
            dwRetBytes -= UsnRecord->RecordLength;
            UsnRecord = (PUSN_RECORD)(((PCHAR)UsnRecord) + UsnRecord->RecordLength);
        }

        ReadData.StartUsn = *(USN*)Buffer;

        counter++;
    }
}

// Function to perform Task Scheduler checks using WMI
void TaskScheduler() {
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

    // Clear the variant
    VariantClear(&processId);

    // Uninitialize WMI interfaces
    UninitializeWMI(pLoc, pSvc);

    // Checks deleted tasks with USN Journal
    HANDLE hVol = OpenVolume();
    USN_JOURNAL_DATA journal = QueryJournal(hVol);
    CheckDeletedTasksInUSNJournal(hVol, journal);
    CloseHandle(hVol);
}
