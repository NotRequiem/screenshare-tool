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

// Function to prompt the user for a file path until a valid path is provided
static std::wstring PromptForFilePath(const std::wstring& promptMessage) {
    std::wstring userInput;
    do {
        try {
            std::wcout << promptMessage;
            std::getline(std::wcin, userInput);

            // Convert the user input to lowercase for case-insensitive comparison
            std::transform(userInput.begin(), userInput.end(), userInput.begin(), ::towlower);

            // Check if the user wants to cancel
            if (userInput == L"cancel") {
                return L""; // Return an empty string to indicate cancellation
            }

            if (userInput.empty()) {
                std::wcerr << L"You entered an empty file path. Please re-enter a valid file path, it should include the file extension without double quotes.\n";
            }

            // Attempt to open the specified file using std::wifstream
            std::wifstream inputFile(userInput.c_str());
            if (inputFile.is_open()) {
                inputFile.close();
                return userInput; // Valid file path provided
            }
            else {
                // Display an error message if the file cannot be opened
                std::wcerr << L"Could not open the file at the specified path. Please re-enter a valid file path, it should include the file extension without double quotes.\n";
            }
        }
        catch (const std::exception& e) {
            std::wcerr << L"Exception occurred: " << e.what() << std::endl;
        }
        catch (...) {
            std::wcerr << L"An unknown exception occurred during file input.\n";
        }

    } while (true);
}

// Function to perform file execution and dll injection checks in csrss memory dumps
void csrss(bool imp) {
    if (!imp) {
        setConsoleTextColor(BrightYellow);
        std::wcout << L"[Memory Scanner] Loading USNJournal into memory...\n";
        resetConsoleTextColor();
    }

    // Run the system command
    std::wstring systemCommand = L"fsutil usn readjournal c: csv | findstr /i /c:0x80000200 /c:0x00001000 >> journal.txt";
    if (_wsystem(systemCommand.c_str()) != 0) {
        return;
    }

    // Set to keep track of already printed matching strings
    std::unordered_set<std::wstring> printedMatches;

    std::wstring filePath1, filePath2;
    std::string journal = "journal.txt";

    // Prompt the user for the first file path
    std::wcout << L"Dump the \"csrss.exe\" process with the MOST private bytes using System Informer and save the results to any directory.\n";
    filePath1 = PromptForFilePath(L"After doing this, enter here the full path of the results file. Type 'cancel' to exit this check if you cant dump csrss or there's no strings inside it: ");
    if (filePath1.empty()) {
        std::filesystem::remove(journal);
        return;  // User canceled, skip to the NTFS Scanner module
    }

    // Prompt the user for the second file path
    std::wcout << L"Now, repeat the same process again, but now dump the \"csrss.exe\" process with the LESS private bytes.\n";
    filePath2 = PromptForFilePath(L"Enter here the full path of the second results file. Type 'cancel' to exit this check if you cant dump csrss or there's no strings inside it: ");
    if (filePath2.empty()) {
        std::filesystem::remove(journal);
        return;  // User canceled, skip to the NTFS Scanner module
    }

    // Attempt to open the specified files
    std::wifstream inputFile1(filePath1.c_str());
    std::wifstream inputFile2(filePath2.c_str());
    std::unordered_set<std::wstring> deletedFileContents = LoadDeletedFileContents(L"journal.txt");

    // I use regular expressions (even if its slower than just doing a search algorithm) to match lines so that the intention of what I match is more clear for other developers

    // Regular expressions for matching modified extensions and executed files
    std::wregex regexModifiedExtension(L"(?!.*(\\.exe|\\.dll|\\\\|\\.dll\\..*\\.config|\\.exe\\.config)$)^[A-Z]:\\\\.*\\..*");
    std::wregex regexDllInjection(L"^[A-Za-z]:\\\\.+?.dll");
    std::wregex regexExecutedFile(L"^[A-Za-z]:\\\\.+?.exe");

    // Define the third regular expression for files executed without extension
    std::wregex regexFilesWithoutExtension1(L"^[A-Za-z]:\\\\(?:[^.\\\\]+\\\\)*[^.\\\\]+$");

    // Define the fourth regular expression for files executed without extension
    std::wregex regexFilesWithoutExtension2(L"^\\\\\\?\\?\\\\(?:[^.\\\\]+\\\\)*[^.\\\\]+$");

    std::wstring line;

    bool fileScanned = false;

    while (!fileScanned) {
        if (!imp) {       
        setConsoleTextColor(BrightYellow);
        std::wcout << L"[Memory Scanner] Scanning DLL Injections...\n";
        std::wcout << L"[Memory Scanner] Scanning executed files with modified extensions...\n";
        std::wcout << L"[Memory Scanner] Scanning executed files without extension...\n";
        std::wcout << L"[Memory Scanner] Scanning executed files without name...\n";
        resetConsoleTextColor();
        }

        try {
            while (std::getline(inputFile1, line)) {
                // Skip lines that exceed the maximum allowed length to avoid crashing
                if (line.length() > MAX_LINE_LENGTH) {
                    continue;
                }

                // csrss string dumps start always with "0x" when done with System Informer, so we need to capture only the file path
                // we consider every file path found in the csrss memory dump as an executed file
                size_t colonPos = line.find(':');
                if (colonPos != std::wstring::npos && colonPos + 2 < line.length()) {
                    std::wstring matchedString = line.substr(colonPos + 2);

                    if (std::regex_search(matchedString, regexModifiedExtension)) {
                        // Check for file existence
                        if (printedMatches.find(matchedString) == printedMatches.end()) {
                            if (!std::filesystem::exists(matchedString)) {

                                if (!screenshare_tool::FileTracker::isFileProcessed(matchedString)) {
                                    if (matchedString.find(L"C:\\") != std::wstring::npos || matchedString.find(L"c:\\") != std::wstring::npos) {
                                        // If the file exists in C:, we check with USNJournal if it was actually deleted to avoid false flags
                                        if (IsLineInDeletedFile(matchedString, deletedFileContents)) {
                                            std::wcout << L"[#] Executed & Deleted file with a modified extension: " << matchedString << std::endl;
                                            screenshare_tool::FileTracker::addProcessedFile(matchedString);
                                        }
                                    }
                                    else {
                                        // If the file was not deleted in the C: drive, we flag it as a deleted file since it will not be a deleted system file
                                        std::wcout << L"[#] Executed & Deleted file with a modified extension: " << matchedString << std::endl;
                                        screenshare_tool::FileTracker::addProcessedFile(matchedString);
                                    }
                                }
                            }
                        }

                        // If the file exists, we check:
                        // If it's unsigned (not legitimate files will not be signed to avoid detections)
                        // If it's a .exe or .dll (since the regex for modified extensions will also capture non-executable files, and we need to avoid false flags).
                        if (std::filesystem::exists(matchedString) && IsPEExecutable(matchedString) && !IsFileSignatureValid(matchedString)) {
                            std::wcout << L"[#] Executed & Unsigned file with a modified extension: " << matchedString << std::endl;
                        }

                        printedMatches.insert(matchedString); // Add to the set to avoid duplicate output
                        continue;  // Jump to the next line. This way, once a line matches a regex, it won't check the remaining regex patterns for the same line.
                    }

                    if (std::regex_search(matchedString, regexDllInjection)) {
                        if (!screenshare_tool::FileTracker::isFileProcessed(matchedString)) {
                            if (std::filesystem::exists(matchedString)) {
                                if (!IsFileSignatureValid(matchedString)) {
                                    std::wcout << L"[#] Executed & Unsigned file: " << matchedString << std::endl;
                                }
                            }
                            else {
                                std::wcout << L"[#] Executed & Deleted file: " << matchedString << std::endl;
                            }

                            // Add to the FileTracker to avoid duplicate output
                            screenshare_tool::FileTracker::addProcessedFile(matchedString);
                        }
                    }

                    if (!screenshare_tool::FileTracker::isFileProcessed(matchedString)) {
                        if (std::regex_search(matchedString, regexFilesWithoutExtension1) || std::regex_search(matchedString, regexFilesWithoutExtension2)) {
                            // Check if the path corresponds to a directory, because directories are sometimes falsely flagged by these regex
                            // Check if the file exists and is not already printed
                            if (!std::filesystem::is_directory(matchedString) && std::filesystem::exists(matchedString)) {
                                std::wcout << L"[#] Executed file without extension: " << matchedString << std::endl;
                            }

                            if (!std::filesystem::exists(matchedString)) {
                                // Check if "C:\" or "c:\" is present in the line to avoid false flagging not really deleted system files
                                if ((matchedString.find(L"C:\\") != std::wstring::npos || matchedString.find(L"c:\\") != std::wstring::npos)) {
                                    if (IsLineInDeletedFile(matchedString, deletedFileContents)) {
                                        std::wcout << L"[#] Executed & Deleted file without extension: " << matchedString << std::endl;
                                    }
                                }
                                else {
                                    // The file was not deleted in C:. Check if the file contains a letter, followed by a colon, and followed by a backslash "\"
                                    size_t backslashPos = matchedString.find(L"\\", colonPos + 1);
                                    if (backslashPos != std::wstring::npos) {
                                        std::wcout << L"[#] Executed & Deleted file without extension (false flags here can't be fixed): " << matchedString << std::endl;
                                    }
                                }
                            }
                        }

                        // Add to the FileTracker to avoid duplicate output
                        screenshare_tool::FileTracker::addProcessedFile(matchedString);
                    }
                }
            }

            inputFile1.close();
            std::filesystem::remove(filePath1);
            std::filesystem::remove("journal.txt");
        }
        catch (const std::exception& e) {
            std::cerr << "[#] The SS Tool has detected and prevented a possible crash. Report this error to Requiem: " << e.what() << std::endl;
        }

        setConsoleTextColor(BrightYellow);
        std::wcout << L"[Memory Scanner] Scanning executed and unsigned files...\n";
        resetConsoleTextColor();

        try {
            while (std::getline(inputFile2, line)) {
                // Skip lines that exceed the maximum allowed length to avoid crashing
                if (line.length() > MAX_LINE_LENGTH) {
                    continue;
                }

                // csrss string dumps start always with "0x" when done with System Informer, so we need to capture only the file path
                // we consider every file path found in the csrss memory dump as an executed file
                size_t colonPos = line.find(':');
                if (colonPos != std::wstring::npos && colonPos + 2 < line.length()) {
                    std::wstring matchedString = line.substr(colonPos + 2);

                    if (!screenshare_tool::FileTracker::isFileProcessed(matchedString)) {
                        if (std::regex_search(matchedString, regexExecutedFile)) {
                            if (std::filesystem::exists(matchedString)) {
                                if (!IsFileSignatureValid(matchedString)) {
                                    std::wcout << L"[#] Executed & Unsigned file: " << matchedString << std::endl;
                                }
                            }
                            else {
                                std::wcout << L"[#] Executed & Deleted file: " << matchedString << std::endl;
                            }

                            // Add to the FileTracker to avoid duplicate output
                            screenshare_tool::FileTracker::addProcessedFile(matchedString);
                        }
                    }
                }
            }

            inputFile2.close();
            fileScanned = true;  // Assuming both files are processed now
            std::filesystem::remove(filePath2);
        }
        catch (const std::exception& e) {
            std::cerr << "[#] The SS Tool has detected and prevented a possible crash. Report this error to Requiem: " << e.what() << std::endl;
        }
    }
}
