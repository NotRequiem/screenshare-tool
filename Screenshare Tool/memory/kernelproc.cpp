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
        return true;  // It's a recognized binary executable
    }
    else {
        return false; // GetBinaryTypeW failed; not a recognized binary
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
    setConsoleTextColor(BrightYellow);
    std::wcout << L"[Memory Scanner] Loading USNJournal into memory..." << std::endl;
    resetConsoleTextColor();

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

        std::wstring filePath1, filePath2;

        // Provide user instructions for the first file
        std::wcout << L"Dump the \"csrss.exe\" process with the MOST private bytes using System Informer and save the results to any directory.\n";
        std::wcout << L"After doing this, enter here the full path of the results file. Type 'cancel' to exit this check if you cant dump csrss or there's no strings inside it: ";        
        std::wstring userInput;
        std::getline(std::wcin, userInput);

        // Convert the user input to lowercase for case-insensitive comparison
        std::transform(userInput.begin(), userInput.end(), userInput.begin(), ::towlower);

        // Check if the user wants to cancel
        if (userInput == L"cancel") {
            return;  // Skip to the NTFS Scanner module
        }

        filePath1 = userInput;

        // Provide user instructions for the second file
        std::wcout << L"Dump the \"csrss.exe\" process with the LESS private bytes using System Informer and save the results to any directory.\n";
        std::wcout << L"After doing this, enter here the full path of the results file. Type 'cancel' to exit this check if you cant dump csrss or there's no strings inside it: "; 
        std::getline(std::wcin, userInput);

        // Convert the user input to lowercase for case-insensitive comparison
        std::transform(userInput.begin(), userInput.end(), userInput.begin(), ::towlower);

        // Check if the user wants to cancel
        if (userInput == L"cancel") {
            return;  // Skip to the NTFS Scanner module
        }

        filePath2 = userInput;

        // Attempt to open the specified files
        std::wifstream inputFile1(filePath1.c_str());
        std::wifstream inputFile2(filePath2.c_str());
        std::unordered_set<std::wstring> deletedFileContents = LoadDeletedFileContents(L"journal.txt");

        if (inputFile1.is_open()) {
            setConsoleTextColor(BrightYellow);
            std::wcout << L"[Memory Scanner] Analyzing suspicious files in the csrss memory dump with the most private bytes..." << std::endl;
            resetConsoleTextColor();
            // I use regular expressions (even if its slower than just doing a search algorithm) to match lines so that the intention of what I match is more clear for other developers

            // Regular expressions for matching modified extensions and executed files
            std::wregex regexModifiedExtension(L"(?!.*(\\.exe|\\.dll|\\\\|\\.dll\\..*\\.config|\\.exe\\.config)$)^[A-Z]:\\\\.*\\..*");
            std::wregex regexDllInjection(L"^[A-Za-z]:\\\\.+\\.dll$");

            // Define the third regular expression for files executed without extension
            std::wregex regexFilesWithoutExtension1(L"^[A-Za-z]:\\\\(?:[^.\\\\]+\\\\)*[^.\\\\]+$");

            // Define the fourth regular expression for files executed without extension
            std::wregex regexFilesWithoutExtension2(L"^\\\\\\?\\?\\\\(?:[^.\\\\]+\\\\)*[^.\\\\]+$");

            std::wstring line;

            while (std::getline(inputFile1, line)) {
                // Skip lines that exceed the maximum allowed length to avoid crashing
                if (line.length() > MAX_LINE_LENGTH) {
                    continue;
                }

                // csrss string dumps starts always with "0x" when done with System Informer, so we need to capture only the file path
                // we consider every file path found in the csrss memory dump as an executed file
                size_t colonPos = line.find(':');
                if (colonPos != std::wstring::npos && colonPos + 2 < line.length()) {
                    std::wstring matchedString = line.substr(colonPos + 2);

                    if (std::regex_search(matchedString, regexModifiedExtension)) {
                        // Check for file existence
                        if (printedMatches.find(matchedString) == printedMatches.end()) {
                            if (!std::filesystem::exists(matchedString)) {

                                if (matchedString.find(L"C:\\") != std::wstring::npos || matchedString.find(L"c:\\") != std::wstring::npos) {

                                    // If the file exists in C:, we check with USNJournal if it was actually deleted to avoid false flags
                                    if (IsLineInDeletedFile(matchedString, deletedFileContents)) {
                                        std::wcout << L"[#] Executed & Deleted file with a modified extension: " << matchedString << std::endl;
                                    }
                                }
                                else {
                                    // If the file was not deleted in the C: drive, we flag it as a deleted file since it will not be a deleted system file
                                    std::wcout << L"[#] Executed & Deleted file with a modified extension: " << matchedString << std::endl;
                                }
                            }
                        }

                        // If the file exists, we check: 
                        // If its unsigned (not legitimate files will not be signed to avoid detections)
                        // If its a .exe or .dll (since the regex for modified extensions will also capture non executable files, and we need to avoid false flags).
                        if (std::filesystem::exists(matchedString) && IsPEExecutable(matchedString) && !IsFileSignatureValid(matchedString)) {
                            std::wcout << L"[#] Executed & Unsigned file with a modified extension: " << matchedString << std::endl;
                        }

                        printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                        continue;  // Jump to the next line. This way, once a line matches a regex, it won't check the remaining regex patterns for the same line.
                    }

                    if (std::regex_search(matchedString, regexDllInjection)) {
                        if (printedMatches.find(matchedString) == printedMatches.end()) {
                            if (std::filesystem::exists(matchedString)) {
                                if (!IsFileSignatureValid(matchedString)) {
                                    std::wcout << L"[#] Executed & Unsigned file: " << matchedString << std::endl;  
                                }
                            }
                            else {
                                    std::wcout << L"[#] Executed & Deleted file: " << matchedString << std::endl;
                            }

                            printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                            continue;  // Jump to the next line. This way, once a line matches a regex, it won't check the remaining regex patterns for the same line.
                        }
                    }

                    if (std::regex_search(matchedString, regexFilesWithoutExtension1) || std::regex_search(matchedString, regexFilesWithoutExtension2)) {
                        // Check if the path corresponds to a directory, because directories are sometimes falsely flagged by these regex
                        // Check if the file exists and is not already printed
                        if (!std::filesystem::is_directory(matchedString) && std::filesystem::exists(matchedString)) {
                            if (printedMatches.find(matchedString) == printedMatches.end()) {
                                std::wcout << L"[#] Executed file without extension: " << matchedString << std::endl;
                            }
                        }

                        if (!std::filesystem::exists(matchedString)) {
                            // Check if "C:\" or "c:\" is present in the line to avoid false flagging not really deleted system files
                            if ((matchedString.find(L"C:\\") != std::wstring::npos || matchedString.find(L"c:\\") != std::wstring::npos)) {
                                if (IsLineInDeletedFile(matchedString, deletedFileContents) && printedMatches.find(matchedString) == printedMatches.end()) {
                                    std::wcout << L"[#] Executed & Deleted file without extension: " << matchedString << std::endl;
                                }
                            }
                            else {
                                // The file was not deleted in C:. Check if the file contains a letter, followed by a colon, and followed by a backslash "\"
                                size_t colonPos = matchedString.find(L":");
                                size_t backslashPos = matchedString.find(L"\\", colonPos + 1);

                                if (colonPos != std::wstring::npos && backslashPos != std::wstring::npos) {
                                    std::wcout << L"[#] Executed & Deleted file without extension (false flags here can't be fixed): " << matchedString << std::endl;
                                }
                            }
                        }

                        printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                        continue;  // Jump to the next line. This way, once a line matches a regex, it won't check the remaining regex patterns for the same line.
                    }
                }
            }

            inputFile1.close();
            fileScanned = true;
            std::filesystem::remove(L"journal.txt");
        }
        else {
            // Display an error message if the csrss memory dump cannot be opened
            std::wcerr << L"Please re-enter a valid file path, it should include the file extension without double quotes.\n";
        }

        if (inputFile2.is_open()) {
            setConsoleTextColor(BrightYellow);
            std::wcout << L"[Memory Scanner] Analyzing suspicious files in the csrss memory dump with the less private bytes..." << std::endl;
            resetConsoleTextColor();
            std::wregex regexExecutedFile(L"^[A-Za-z]:\\\\.+\\.exe$");

            std::wstring line;

            while (std::getline(inputFile2, line)) {
                // Skip lines that exceed the maximum allowed length to avoid crashing
                if (line.length() > MAX_LINE_LENGTH) {
                    continue;
                }

                // csrss string dumps starts always with "0x" when done with System Informer, so we need to capture only the file path
                // we consider every file path found in the csrss memory dump as an executed file
                size_t colonPos = line.find(':');
                if (colonPos != std::wstring::npos && colonPos + 2 < line.length()) {
                    std::wstring matchedString = line.substr(colonPos + 2);

                    if (std::regex_search(matchedString, regexExecutedFile)) {
                        if (printedMatches.find(matchedString) == printedMatches.end()) {
                            if (std::filesystem::exists(matchedString)) {
                                if (!IsFileSignatureValid(matchedString)) {
                                    std::wcout << L"[#] Executed & Unsigned file: " << matchedString << std::endl;
                                }
                            }
                            else {
                                std::wcout << L"[#] Executed & Deleted file: " << matchedString << std::endl;
                            }

                            printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                            continue;  // Jump to the next line. This way, once a line matches a regex, it won't check the remaining regex patterns for the same line.
                        }
                    }
                }
            }

            inputFile2.close();
            fileScanned = true;  // Assuming both files are processed now
            std::filesystem::remove(filePath2);
        }
        else {
            // Display an error message if the csrss memory dump with the less private bytes cannot be opened
            std::wcerr << L"Please re-enter a valid file path, it should include the file extension without double quotes.\n";
            return;
        }
    }
}