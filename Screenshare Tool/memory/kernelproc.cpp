#include "..\digital signature\trustverify.hpp"
#include "kernelproc.hpp"

// Function to compare two strings in a case-insensitive manner
bool CaseInsensitiveCompare(const std::wstring& str1, const std::wstring& str2) {
    return std::equal(str1.begin(), str1.end(), str2.begin(), str2.end(),
        [](wchar_t ch1, wchar_t ch2) {
            return std::towlower(ch1) == std::towlower(ch2);
        });
}

// Function to check if a file signature is valid
bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

// Function to check if a file is actually deleted to avoid false flags
bool IsLineInDeletedFile(const std::wstring& lineToCheck) {
    std::wifstream deletedFile("journal.txt");
    if (deletedFile.is_open()) {
        std::wstring fileContent((std::istreambuf_iterator<wchar_t>(deletedFile)), std::istreambuf_iterator<wchar_t>());
        deletedFile.close();

        size_t found = fileContent.find(lineToCheck);
        return found != std::wstring::npos;
    }

    return false;
}

// Function to check if a file with modified extension is actually an executable
bool IsPEExecutable(const std::wstring& filePath) {
    DWORD fileType = 0;

    if (GetBinaryTypeW(filePath.c_str(), &fileType) != 0) {
        // Check if it's a DLL
        if (fileType == SCS_32BIT_BINARY || fileType == SCS_64BIT_BINARY) {
            return true; // It's an EXE
        }
        else {
            // Additional DLL checks
            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                // Read the PE header to check if it's a DLL
                IMAGE_DOS_HEADER dosHeader{};
                DWORD bytesRead;
                if (ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) &&
                    bytesRead == sizeof(dosHeader) &&
                    dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                    // Move to the PE header
                    if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
                        // Read the PE signature
                        DWORD peSignature = 0;
                        if (ReadFile(hFile, &peSignature, sizeof(peSignature), &bytesRead, NULL) &&
                            bytesRead == sizeof(peSignature) &&
                            peSignature == IMAGE_NT_SIGNATURE) {
                            // Read the PE header
                            IMAGE_FILE_HEADER fileHeader{};
                            if (ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, NULL) &&
                                bytesRead == sizeof(fileHeader) &&
                                (fileHeader.Characteristics & IMAGE_FILE_DLL)) {
                                CloseHandle(hFile);
                                return true; // It's a DLL
                            }
                        }
                    }
                }

                CloseHandle(hFile);
            }

            return false; // Not an EXE or DLL
        }
    }
    else {
        return false; // GetBinaryTypeW failed
    }
}

// Function to perform file execution and dll injection checks in csrss memory dumps
void csrss() {
    std::wcout << L"Analyzing deleted files registered by usn journal before running checks for files executed with modified extensions..." << std::endl;

    system("fsutil usn readjournal c: csv | findstr /i /c:0x80000200 /c:0x00001000 >> journal.txt");
    SetFileAttributesW(L"journal.txt", FILE_ATTRIBUTE_HIDDEN);
    std::wstring filePath;

    // Set to keep track of already printed matching strings
    std::set<std::wstring> printedMatches;

    bool fileScanned = false;

    while (!fileScanned) {
        // Provide user instructions
        std::wcout << L"Dump the \"csrss.exe\" process with the most private bytes using System Informer and save the results to any directory." << std::endl;
        std::wcout << L"After doing this, enter the full path of the results file (or type 'cancel' to skip this check): ";
        std::getline(std::wcin, filePath);

        // Check if the user wants to cancel the csrss checks
        if (CaseInsensitiveCompare(filePath, L"cancel")) {
            std::wcout << L"csrss checks skipped. Running next check..." << std::endl;
            return;
        }

        // Attempt to open the specified file
        std::wifstream inputFile(filePath.c_str());

        if (inputFile.is_open()) {
            // Define regular expressions for matching modified extensions and executed files
            std::wregex regexModifiedExtension(L"(?!.*(\\.exe|\\.dll|\\\\|\\.dll\\..*\\.config|\\.exe\\.config)$)^[A-Z]:\\\\.*\\..*");
            std::wregex regexExecutedFile(L"^[A-Za-z]:\\\\.+\\.(exe|dll)$");

            // Define the third regular expression for files executed without extension
            std::wregex regexFilesWithoutExtension1(L"^[A-Za-z]:\\\\(?:[^.\\\\]+\\\\)*[^.\\\\]+$");

            // Define the fourth regular expression for files executed without extension
            std::wregex regexFilesWithoutExtension2(L"^\\\\\\?\\?\\\\(?:[^.\\\\]+\\\\)*[^.\\\\]+$");

            std::wstring line;
            bool contains0x = false;  // Flag to check if lines starting with "0x" exist

            while (std::getline(inputFile, line)) {
                // Skip lines that exceed the maximum allowed length
                if (line.length() > MAX_LINE_LENGTH) {
                    continue;
                }

                if (!contains0x && line.compare(0, 2, L"0x") == 0) {
                    contains0x = true;
                }

                // Check if the line starts with "0x" to handle cases where people extract the results file by only copying the file paths
                if (!contains0x) {
                    // Check for regexModifiedExtension or regexExecutedFile in the line
                    if (std::regex_search(line, regexModifiedExtension) || std::regex_search(line, regexExecutedFile)) {
                        // Check for file existence
                        if (printedMatches.find(line) == printedMatches.end()) {
                            if (std::filesystem::exists(line)) {
                                if (!IsFileSignatureValid(line) && IsPEExecutable(line)) {
                                    std::wcout << L"Executed & unsigned file: " << line << std::endl;
                                }
                            }
                            else if ((line.find(L"C:\\") != std::wstring::npos || line.find(L"c:\\") != std::wstring::npos) &&
                                IsLineInDeletedFile(line)) {
                                std::wcout << L"A Deleted & Executed file: " << line << std::endl;
                            }
                            else {
                                std::wcout << L"Deleted & Executed file: " << line << std::endl;
                            }
                            printedMatches.insert(line); // Add to the set to avoid duplicate output
                        }
                    }

                    if (std::regex_search(line, regexFilesWithoutExtension1) || std::regex_search(line, regexFilesWithoutExtension2)) {
                        // Check if the path corresponds to a directory because directories are sometimes falsely flagged by this regex
                        if (!std::filesystem::is_directory(line) && std::filesystem::exists(line)) {
                            // Check if the file exists and not already printed
                            if (printedMatches.find(line) == printedMatches.end()) {
                                std::wcout << L"Executed file without extension: " << line << std::endl;

                                // Check if "C:\" or "c:\" is present in the line to avoid false flagging not really deleted system files
                                if ((line.find(L"C:\\") != std::wstring::npos || line.find(L"c:\\") != std::wstring::npos) &&
                                    IsLineInDeletedFile(line) && printedMatches.find(line) == printedMatches.end()) {
                                    std::wcout << L"Deleted & Executed file without extension: " << line << std::endl;
                                }
                                else { // The file was not deleted in C:. Then, we just flag the deletion because its not a deleted system file:
                                    std::wcout << L"Deleted & Executed file without extension: " << line << std::endl;
                                }
                                printedMatches.insert(line); // Add to the set to avoid duplicate output
                            }
                        }
                    }
                }
                else {
                    // If the line starts with "0x", (meaning the user just extracted all strings by copying every column), capture only the file path
                    size_t colonPos = line.find(':');
                    if (colonPos != std::wstring::npos && colonPos + 2 < line.length()) {
                        std::wstring matchedString = line.substr(colonPos + 2);

                        if (std::regex_search(matchedString, regexModifiedExtension) || std::regex_search(matchedString, regexExecutedFile)) {
                            // Check for file existence
                            if (printedMatches.find(matchedString) == printedMatches.end()) {
                                if (std::filesystem::exists(matchedString)) {
                                    if (!IsFileSignatureValid(matchedString) && IsPEExecutable(matchedString)) {
                                        std::wcout << L"Executed & unsigned file: " << matchedString << std::endl;
                                    }
                                }
                                else if ((matchedString.find(L"C:\\") != std::wstring::npos || matchedString.find(L"c:\\") != std::wstring::npos) &&
                                    IsLineInDeletedFile(matchedString)) {
                                    std::wcout << L"A Deleted & Executed file: " << matchedString << std::endl;
                                }
                                else {
                                    std::wcout << L"Deleted & Executed file: " << matchedString << std::endl;
                                }
                                printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                            }
                        }

                        if (std::regex_search(matchedString, regexFilesWithoutExtension1) || std::regex_search(matchedString, regexFilesWithoutExtension2)) {
                            // Check if the path corresponds to a directory because directories are sometimes falsely flagged by this regex
                            if (!std::filesystem::is_directory(matchedString) && std::filesystem::exists(matchedString)) {
                                // Check if the file exists and not already printed
                                if (printedMatches.find(matchedString) == printedMatches.end()) {
                                    std::wcout << L"Executed file without extension: " << matchedString << std::endl;

                                    // Check if "C:\" or "c:\" is present in the matchedString
                                    if ((matchedString.find(L"C:\\") != std::wstring::npos || matchedString.find(L"c:\\") != std::wstring::npos) &&
                                        IsLineInDeletedFile(matchedString) && printedMatches.find(matchedString) == printedMatches.end()) {
                                        std::wcout << L"Deleted & Executed file without extension: " << matchedString << std::endl;
                                    }
                                    else {
                                        std::wcout << L"Deleted & Executed file without extension: " << matchedString << std::endl;
                                    }
                                    printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                                }
                            }
                        }
                    }
                }
            }

            fileScanned = true;
            inputFile.close();
            std::filesystem::remove(L"journal.txt");
        }
        else {
            // Display an error message if the csrss memory dump cannot be opened
            std::wcerr << L"Error opening the csrss results file. Please re-enter a valid file path and ensure your result file is not opened by any other program." << std::endl;
        }
    }
}