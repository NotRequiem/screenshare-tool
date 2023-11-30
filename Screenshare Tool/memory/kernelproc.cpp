#include "..\digital signature\trustverify.hpp"
#include "..\gui\color.hpp"
#include "kernelproc.hpp"

// Function to check if a file signature is valid
static bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

// Function to check if a file with modified extension is actually an executable
static bool IsPEExecutable(const std::wstring& filePath) {
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

static std::unordered_set<std::wstring> LoadDeletedFileContents(const std::wstring& journalFilePath) {
    std::wifstream deletedFile(journalFilePath);
    std::unordered_set<std::wstring> contentSet;

    if (deletedFile.is_open()) {
        std::wstring line;
        while (std::getline(deletedFile, line)) {
            contentSet.insert(line);
        }

        deletedFile.close();
    }

    return contentSet;
}

static bool IsLineInDeletedFile(const std::wstring& lineToCheck, const std::unordered_set<std::wstring>& contentSet) {
    return contentSet.find(lineToCheck) != contentSet.end();
}

// Function to perform file execution and dll injection checks in csrss memory dumps
void csrss() {
    Console::SetColor(ConsoleColor::Cyan, ConsoleColor::Black);
    std::wcout << L"[NTFS Scanner] Loading deleted files into memory..." << std::endl;
    Console::ResetColor();

    // Run the system command
    std::wstring systemCommand = L"fsutil usn readjournal c: csv | findstr /i /c:0x80000200 /c:0x00001000 >> journal.txt";
    if (_wsystem(systemCommand.c_str()) != 0) {
        return;
    }


    std::wstring filePath;

    // Set to keep track of already printed matching strings
    std::set<std::wstring> printedMatches;

    bool fileScanned = false;

    while (!fileScanned) {

        // Provide user instructions
        std::wcout << L"Dump the \"csrss.exe\" process with the most private bytes using System Informer and save the results to any directory.\n";
        std::wcout << L"After doing this, enter the full path of the results file: ";
        std::getline(std::wcin, filePath);

        // Attempt to open the specified file
        std::wifstream inputFile(filePath.c_str());
        std::unordered_set<std::wstring> deletedFileContents = LoadDeletedFileContents(L"journal.txt");

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

                // If the line starts with "0x", (meaning the user just extracted all strings by copying every column), capture only the file path
                size_t colonPos = line.find(':');
                if (colonPos != std::wstring::npos && colonPos + 2 < line.length()) {
                    std::wstring matchedString = line.substr(colonPos + 2);

                    if (std::regex_search(matchedString, regexModifiedExtension) || std::regex_search(matchedString, regexExecutedFile)) {
                        // Check for file existence
                        if (printedMatches.find(matchedString) == printedMatches.end()) {
                            if (!std::filesystem::exists(matchedString)) {
                                if (matchedString.find(L"C:\\") == std::wstring::npos && matchedString.find(L"c:\\") == std::wstring::npos) {
                                    // If the path does not contain "C:" or "c:", flag it
                                    std::wcout << L"[#] Deleted & Executed file: " << matchedString << std::endl;
                                }
                                else {
                                    // Check if the path is in the deleted file on the "C:" drive
                                    if (IsLineInDeletedFile(matchedString, deletedFileContents)) {
                                        std::wcout << L"[#] Deleted & Executed file: " << matchedString << std::endl;
                                    }
                                }
                            }

                            if (std::filesystem::exists(matchedString) && !IsFileSignatureValid(matchedString) && IsPEExecutable(matchedString)) {
                                std::wcout << L"[#] Executed & Unsigned file: " << matchedString << std::endl;
                            }

                            printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                        }
                    }

                    if (std::regex_search(matchedString, regexFilesWithoutExtension1) || std::regex_search(matchedString, regexFilesWithoutExtension2)) {
                        // Check if the path corresponds to a directory because directories are sometimes falsely flagged by this regex
                        if (!std::filesystem::is_directory(matchedString) && std::filesystem::exists(matchedString)) {
                            // Check if the file exists and not already printed
                            if (printedMatches.find(matchedString) == printedMatches.end()) {
                                std::wcout << L"[#] Executed file without extension: " << matchedString << std::endl;
                            }
                            printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                        }

                        if (!std::filesystem::exists(matchedString)) {
                            // Check if "C:\" or "c:\" is present in the line to avoid false flagging not really deleted system files
                            if ((matchedString.find(L"C:\\") != std::wstring::npos || matchedString.find(L"c:\\") != std::wstring::npos)) {
                                if (IsLineInDeletedFile(matchedString, deletedFileContents) && printedMatches.find(matchedString) == printedMatches.end()) {
                                    std::wcout << L"[#] Deleted & Executed file without extension: " << matchedString << std::endl;
                                }
                            }
                            else { // The file was not deleted in C:. Then, we just flag the deletion because it is not a deleted system file:
                                std::wcout << L"[#] Deleted & Executed file without extension (false flags here cant be fixed): " << matchedString << std::endl;
                            }
                            printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                        }
                    }
                }
            }

            inputFile.close();
            fileScanned = true;
            std::filesystem::remove(L"journal.txt");
        }
        else {
            // Display an error message if the csrss memory dump cannot be opened
            std::wcerr << L"Please re-enter a valid file path.\n";
        }
    }
}