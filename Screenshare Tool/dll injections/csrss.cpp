#include "csrss.hpp"
#include "..\Digital Signature\trustverify.hpp"

const int MAX_LINE_LENGTH = 400;

void CsrssCheck::csrss() {
    std::wstring filePath;

    while (true) {
        std::wcout << L"The tool uses csrss to enhance the detectability of executed files, dll injections and executed files with modified extensions." << std::endl;
        std::wcout << L"Dump the \"csrss.exe\" process with the most private bytes using System Informer/Process Hacker and save the results to any directory." << std::endl;
        std::wcout << L"After dumping csrss, enter the full path of the results file (or type 'cancel' to skip this check): ";
        std::getline(std::wcin, filePath);

        if (CsrssCheck::CaseInsensitiveCompare(filePath, L"cancel")) {
            std::wcout << L"csrss checks skipped. Running next check..." << std::endl;
            return;
        }

        std::wifstream inputFile(filePath.c_str());

        if (inputFile.is_open()) {
            std::wregex regexModifiedExtension(L"(?!.*(\\.exe|\\.dll|\\\\|\\.dll\\..*\\.config|\\.exe\\.config)$)^[A-Z]:\\\\.*\\..*");
            std::wregex regexExecutedFile(L"^[A-Za-z]:\\\\.+\\.(exe|dll)$");

            std::wstring line;
            while (std::getline(inputFile, line)) {
                if (line.length() > MAX_LINE_LENGTH) {
                    continue;
                }

                // Check if the line starts with "0x" to handle cases where people extract the results file by only copying the file paths
                if (line.compare(0, 2, L"0x") != 0) {
                    // Match the regex directly on the entire line
                    if (std::regex_search(line, regexModifiedExtension) || std::regex_search(line, regexExecutedFile)) {
                        if (!CsrssCheck::IsFileSignatureValid(line)) {
                            std::wcout << L"Executed & unsigned file: " << line << std::endl;
                        }
                    }
                }
                else {
                    // If the line starts with "0x", (meaning the user just extracted all strings by copying every column), capture only the file path
                    size_t colonPos = line.find(':');
                    if (colonPos != std::wstring::npos && colonPos + 2 < line.length()) {
                        std::wstring matchedString = line.substr(colonPos + 2);

                        if (std::regex_search(matchedString, regexModifiedExtension) || std::regex_search(matchedString, regexExecutedFile)) {
                            if (!CsrssCheck::IsFileSignatureValid(matchedString)) {
                                std::wcout << L"Executed & unsigned file: " << matchedString << std::endl;
                            }
                        }
                    }
                }
            }

            inputFile.close();

        }
        else {
            std::wcerr << L"Error opening the csrss results file. Please re-enter a valid file path and ensure your result file is not opened by any other program." << std::endl;
        }
    }
}

bool CsrssCheck::IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

bool CsrssCheck::CaseInsensitiveCompare(const std::wstring& str1, const std::wstring& str2) {
    return std::equal(str1.begin(), str1.end(), str2.begin(), str2.end(),
        [](wchar_t ch1, wchar_t ch2) {
            return std::towlower(ch1) == std::towlower(ch2);
        });
}
