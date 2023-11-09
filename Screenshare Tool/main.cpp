#include "main.hpp"

bool IsRunningAsAdmin() {
    // Check if the sreenshare tool has administrator privileges
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
        if (!CheckTokenMembership(NULL, AdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(AdminGroup);
    }
    return isAdmin;
}

int main(int argc, char* argv[]) {
    if (!IsRunningAsAdmin()) {
        std::cout << "Open this screenshare tool as administrator." << std::endl;
        return 1;
    }

    // ------------------------------------------------------------------------------------------------
    // CUSTOM PROCESS STRING SCANNER
    // ------------------------------------------------------------------------------------------------

    /** Define custom strings to search in processes
     * First parameter: Process name
     * Second parameter: String to search
     * Third parameter: If the scanner should filter the string as a regular expression (true) or not (false)
    */
    std::vector<std::tuple<const wchar_t*, std::wstring, bool>> processParameters = {
        std::make_tuple(L"lghub_agent.exe", L"durationms.+\"isDown\"", true),
        std::make_tuple(L"Razer Synapse.exe", L"DeleteMacroEvent", false),
        std::make_tuple(L"Razer Synapse 3.exe", L"SetKeysPerSecond", false),
        std::make_tuple(L"RazerCentralService.exe", L"Datasync: Status: COMPLETE Action: NONE Macros/", false),
        std::make_tuple(L"SteelSeriesGGClient.exe", L"delay.+is_deleted", true),
        std::make_tuple(L"Onikuma.exe", L"LeftKey CODE:", false),
        std::make_tuple(L"explorer.exe", L"file:///.+?(.bat|.vbs)", false)
    };

    for (const auto& params : processParameters) {
        const wchar_t* processName = std::get<0>(params);
        std::wstring searchPattern = std::get<1>(params);
        bool useRegex = std::get<2>(params);

        scanProcessStrings(processName, searchPattern, useRegex);
    }

    // ------------------------------------------------------------------------------------------------
    // CUSTOM SERVICE STRING SCANNER
    // ------------------------------------------------------------------------------------------------

    HRESULT hr;
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;

    hr = InitializeWMI(pLoc, pSvc);
    if (FAILED(hr)) {
        std::cerr << "WMI initialization failed with error: " << hr << std::endl;
        return 1;
    }

    /** Define custom strings to search in processes
     * First parameter: Service name
     * Second parameter: String to search
     * Third parameter: If the scanner should filter the string as a regular expression (true) or not (false)
    */

    std::vector<std::tuple<const wchar_t*, std::wstring, bool>> serviceParameters = {
        std::make_tuple(L"PlugPlay", L"jar", false),
        std::make_tuple(L"PcaSvc", L".bat", false),
    };

    for (const auto& params : serviceParameters) {
        const wchar_t* serviceName = std::get<0>(params);
        VARIANT processId;
        VariantInit(&processId);

        hr = ExecuteWMIQuery(pSvc, serviceName, processId);
        if (SUCCEEDED(hr)) {
            std::wcout << serviceName << L" Scanning strings on process: " << processId.intVal << std::endl;

            scanServiceStrings(serviceName, std::get<1>(params), std::get<2>(params));

            VariantClear(&processId);
        } else {
            std::cerr << "WMI query for " << serviceName << " failed with error: " << hr << std::endl;
        }
    }

    UninitializeWMI(pLoc, pSvc);

    // ------------------------------------------------------------------------------------------------
    // BAM CHECKS
    // ------------------------------------------------------------------------------------------------

    bool running = IsBAMRunning();
    if (!running) {
        std::cout << "The Background Activity Moderator service is not running, therefore checks for modified extensions, files without extensions and files without names won't run." << std::endl;
    }

    // ------------------------------------------------------------------------------------------------
    // DLL INJECTION CHECKS
    // ------------------------------------------------------------------------------------------------

    std::vector<std::wstring> ntfsDrives = getNTFSDrives();

    if (!ntfsDrives.empty()) {
        for (const std::wstring& drive : ntfsDrives) {
            wchar_t currentDir[MAX_PATH];
            if (GetCurrentDirectoryW(MAX_PATH, currentDir) > 0) {
                std::wstring mfteCmdPath = currentDir;
                mfteCmdPath += L"\\MFTECmd.exe";

                std::wstring arguments = L"-f " + drive + L":\\$MFT --csv .";
                runMFTECmd(mfteCmdPath, arguments, drive);
            }
        }
    }

    // ------------------------------------------------------------------------------------------------
    // FILE MACRO CHECKS
    // ------------------------------------------------------------------------------------------------

    wchar_t username[MAX_PATH];
    DWORD usernameSize = MAX_PATH;
    if (GetUserNameW(username, &usernameSize)) {
        CheckRecentFileModifications();
    }

    // ------------------------------------------------------------------------------------------------
    // USN JOURNAL CLEARED CHECKS
    // ------------------------------------------------------------------------------------------------
    std::vector<std::wstring> driveLetters = GetDriveLetters();

    for (const std::wstring& driveLetter : driveLetters) {
        CheckDriveJournal(driveLetter);
    }

    // ------------------------------------------------------------------------------------------------
    // VIRTUAL MACHINE CHECKS
    // ------------------------------------------------------------------------------------------------
    if (VM::detect()) {
        std::cout << "Virtual machine detected. It can be used to send mouse events between physical and virtual machines in order to autoclick." << std::endl;
    }
    else {
        std::cout << "This user is not using a Virtual Machine" << std::endl;
    }

    ReplacedFiles(); // REPLACED FILE CHECKS //
    CheckDiskInstallation(); // REPLACED DISK CHECKS //

    // ------------------------------------------------------------------------------------------------
    // RAM CHECKS
    // ------------------------------------------------------------------------------------------------
    InitializeLowercaseConversionTable();

    std::string filename;
    std::vector<char> buffer;
    std::string overlapData;
    std::unordered_set<std::string> printedMatches;
    std::unique_ptr<std::ostream> output;

    // Check if a filename is provided as a command-line argument, otherwise prompt the user to enter a file path
    if (argc > 1) {
        filename = argv[1];
    }
    else {
        std::cout << "Enter the file path of your RAM memory dump (Example: D:\\Downloads\\memdump.mem): ";
        std::getline(std::cin, filename);
    }

    char outputChoice;
    bool validChoice = false;

    // Prompt the user for the output choice (console or file) and validate the input
    while (!validChoice) {
        std::cout << "Do you want to print the matched strings to the console (C) or to a file (F)? ";
        std::cin >> outputChoice;

        // Clear the input buffer
        while (std::cin.get() != '\n') {
            // Continue reading characters and do nothing with them until a newline is found
        }

        if (outputChoice == 'C' || outputChoice == 'c' || outputChoice == 'F' || outputChoice == 'f') {
            validChoice = true;
        }
        else {
            std::cerr << "Invalid choice. Please enter 'C' for console or 'F' for file." << std::endl;
        }
    }

    std::ifstream file(filename, std::ios::binary | std::ios::in);

    // Check if the file can be opened; if not, display an error message
    if (!file.is_open()) {
        std::cerr << "Failed to open the file, probably because it is already opened by another application or you provided a wrong path." << std::endl;
        return 1;
    }

    // If the output choice is a file, open an output file for writing
    if (outputChoice == 'F' || outputChoice == 'f') {
        std::string outputFilePath = "memparser_results.txt";
        output = std::make_unique<std::ofstream>(outputFilePath);

        // Check if the output file can be opened; if not, display an error message
        if (!output->good()) {
            std::cerr << "Failed to open the output file. Try to select the 'C' option to print results to the console if this keeps happening." << std::endl;
            return 1;
        }
    }

    // Get the file size to determine the appropriate chunk size
    file.seekg(0, std::ios::end);
    size_t fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    // Determine the chunk size based on the file size
    size_t chunkSize = (fileSize > MIN_CHUNK_SIZE) ? MIN_CHUNK_SIZE : fileSize;
    buffer.resize(chunkSize);

    if (outputChoice == 'F' || outputChoice == 'f') {
        std::string outputFilePath = "memparser_results.txt";
        output = std::make_unique<std::ofstream>(outputFilePath);

        if (!output->good()) {
            std::cerr << "Failed to open the output file. Try to select the 'C' option to print results to the console if this keeps happening." << std::endl;
            return 1;
        }
    }

    bool done = false;

    // Process the memory image in chunks
    while (!done) {
        file.read(buffer.data(), chunkSize);
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            std::string data(buffer.data(), static_cast<size_t>(bytesRead));
            // Append any remaining overlapData from the previous chunk to the current data.
            data = overlapData + data;
            // Clear the overlapData variable as it has been processed.
            overlapData.clear();

            /**
             * The overlapData variable is used to handle overlapping data between successive chunks of data read from a memory image file.
             * The program processes the memory image file in chunks for more efficient data processing.
             * overlapData is employed to ensure that any partial information at the end of one chunk is retained and combined with the data in the next chunk.
             * This prevents splitting and processing of incomplete information that might span across two chunks.
            */

            size_t pos1, pos2;

            /**
                Search for specific substrings in the data, process and print them.
                These searches are related to file access or execution evidence.
                Also, they handle different formats of the same information.
            */

            /**
             * "file:///" -> Explorer string (evidence of file accessed/opened).
             * "ImageName" -> SgrmBroker string.
             * "AppPath" -> CDPUserSvc and TextInputHost strings.
             * "!!" -> DPS string (indicating compilation time of an executable).
             * "\??\" -> Explorer and csrss string (evidence of execution).
             * "java -jar" -> DcomLaunch & WMI strings (evidence of jar execution)
             * ".exe" and ". e x e" -> ending of any substring (with or without spaces).
            */

            // The matching substrings are passed to ProcessMatchingString for cleaning and printing

            // Search for occurrences of "file:///" pattern in the input data to detect executable files
            pos1 = data.find("file:///");

            // If the pattern "file:///" is found in the data string:
            if (pos1 != std::string::npos) {
                // Extract a substring starting from the position of the pattern.
                auto dataSubstring = data.substr(pos1);

                // Search for the ".exe" pattern within the extracted substring.
                auto it = std::search(dataSubstring.begin(), dataSubstring.end(), ".exe", ".exe" + 4,
                    [](char a, char b) {
                        return ConvertToLowercase(a) == ConvertToLowercase(b);
                    });

                // Check for additional occurrences of "file:///" between pos1 and it.
                bool hasFileOccurrences = false;
                for (auto it2 = dataSubstring.begin() + 7; it2 < it; ++it2) {
                    if (std::equal(it2, it2 + 7, "file:///")) {
                        hasFileOccurrences = true;
                        break;
                    }
                }

                // Check for the presence of special characters between "file:///" and ".exe".
                bool hasSpecialCharactersBetween = false;
                const std::string specialCharacters = "*\"<>?|:\\";
                for (auto it2 = dataSubstring.begin() + 7; it2 < it; ++it2) {
                    if (specialCharacters.find(*it2) != std::string::npos) {
                        hasSpecialCharactersBetween = true;
                        break;
                    }
                }

                // Check for the presence of a slash "/" between "file:///" and ".exe".
                bool hasSlashBetween = false;
                auto slashPosition = std::find(dataSubstring.begin() + 8, it, '/');
                if (slashPosition != it) {
                    hasSlashBetween = true;
                }

                // If there are no additional "file:///" between the initial "file:///" and ".exe",
                // and there are no special characters and there is a slash "/" between them:
                if (!hasFileOccurrences && !hasSpecialCharactersBetween && hasSlashBetween && it != dataSubstring.end()) {
                    // Calculate the end position of the matched substring.
                    size_t pos2 = pos1 + static_cast<size_t>(std::distance(dataSubstring.begin(), it));

                    // Extract the matched string, including "file:///" and the ".exe" extension.
                    std::string match = data.substr(pos1, pos2 - pos1 + 4);

                    // Process the matching string using a function named ProcessMatchingString.
                    ProcessMatchingString(match, printedMatches, outputChoice, output);
                }
            }

            // Search for occurrences of "file:///" pattern in the input data to detect batch files
            pos1 = data.find("file:///");

            // If the pattern "file:///" is found in the data string:
            if (pos1 != std::string::npos) {
                // Extract a substring starting from the position of the pattern.
                auto dataSubstring = data.substr(pos1);

                // Search for the ".bat" pattern within the extracted substring.
                auto it = std::search(dataSubstring.begin(), dataSubstring.end(), ".bat", ".bat" + 4,
                    [](char a, char b) {
                        return ConvertToLowercase(a) == ConvertToLowercase(b);
                    });

                // Check for additional occurrences of "file:///" between pos1 and it.
                bool hasFileOccurrences = false;
                for (auto it2 = dataSubstring.begin() + 7; it2 < it; ++it2) {
                    if (std::equal(it2, it2 + 7, "file:///")) {
                        hasFileOccurrences = true;
                        break;
                    }
                }

                // Check for the presence of special characters between "file:///" and ".bat".
                bool hasSpecialCharactersBetween = false;
                const std::string specialCharacters = "*\"<>?|:\\";
                for (auto it2 = dataSubstring.begin() + 7; it2 < it; ++it2) {
                    if (specialCharacters.find(*it2) != std::string::npos) {
                        hasSpecialCharactersBetween = true;
                        break;
                    }
                }

                // Check for the presence of a slash "/" between "file:///" and ".bat".
                bool hasSlashBetween = false;
                auto slashPosition = std::find(dataSubstring.begin() + 8, it, '/');
                if (slashPosition != it) {
                    hasSlashBetween = true;
                }

                // If there are no additional "file:///" between the initial "file:///" and ".bat",
                // and there are no special characters and there is a slash "/" between them:
                if (!hasFileOccurrences && !hasSpecialCharactersBetween && hasSlashBetween && it != dataSubstring.end()) {
                    // Calculate the end position of the matched substring.
                    size_t pos2 = pos1 + static_cast<size_t>(std::distance(dataSubstring.begin(), it));

                    // Extract the matched string, including "file:///" and the ".bat" extension.
                    std::string match = data.substr(pos1, pos2 - pos1 + 4);

                    // Process the matching string using a function named ProcessMatchingString.
                    ProcessMatchingString(match, printedMatches, outputChoice, output);
                }
            }

            // Handle the "ImageName" pattern
            pos1 = data.find("\"ImageName\":\"");
            if (pos1 != std::string::npos) {
                auto dataSubstring = data.substr(pos1);
                auto it = std::search(dataSubstring.begin(), dataSubstring.end(), ".exe\"", ".exe\"" + 4, // Increment +4 to include the ".exe" extension.
                    [](char a, char b) {
                        return ConvertToLowercase(a) == ConvertToLowercase(b);
                    });

                // Check for the presence of special characters between "ImageName":" and ".exe".
                bool hasSpecialCharactersBetween = false;
                const std::string specialCharacters = "*\"<>?|:\\";
                for (auto it2 = dataSubstring.begin() + 13; it2 < it; ++it2) {
                    if (specialCharacters.find(*it2) != std::string::npos) {
                        hasSpecialCharactersBetween = true;
                        break;
                    }
                }

                if (it != dataSubstring.end() && !hasSpecialCharactersBetween) {
                    pos2 = pos1 + static_cast<size_t>(std::distance(dataSubstring.begin(), it));
                    // Increment +13 here to skip the "ImageName":" part of the string, leaving only the device path.
                    std::string match = data.substr(pos1 + 13, pos2 - pos1 - 13 + 4);
                    ProcessMatchingString(match, printedMatches, outputChoice, output);
                }
            }

            // Handle the "AppPath" pattern
            pos1 = data.find("\"AppPath\":\"");
            if (pos1 != std::string::npos) {
                pos1 += 12; // Move past "AppPath":"
                auto dataSubstring = data.substr(pos1);

                // Check if the first character in dataSubstring is an alphabetic character
                if (dataSubstring.size() > 0 && std::isalpha(dataSubstring[0])) {
                    auto it = std::search(dataSubstring.begin(), dataSubstring.end(), ".exe", ".exe" + 4, // Increment +4 here to include the ".exe" extension.
                        [](char a, char b) {
                            return ConvertToLowercase(a) == ConvertToLowercase(b);
                        });

                    if (it != dataSubstring.end()) {
                        pos2 = pos1 + static_cast<size_t>(std::distance(dataSubstring.begin(), it));
                        std::string match = data.substr(pos1, pos2 - pos1 + 4); // Increment +4 here to include the ".exe" extension
                        ProcessMatchingString(match, printedMatches, outputChoice, output);
                    }
                }
            }

            // Search for "!!" in the input string, if not found, search for "! !"
            pos1 = data.find("!!");
            if (pos1 == std::string::npos) {
                pos1 = data.find("! !");
            }

            // If "!!" or "! !" is found in the input data
            if (pos1 != std::string::npos) {
                std::string searchString = ".exe!";
                std::string searchStringWithSpaces = ". e x e !";
                size_t pos2 = pos1;

                // Search for ".exe!" or ". e x e !" with spaces
                pos2 = data.find(searchString, pos1);
                if (pos2 == std::string::npos) {
                    pos2 = data.find(searchStringWithSpaces, pos1);
                }

                // If ".exe!" or ". e x e !" is found:
                if (pos2 != std::string::npos) {
                    // Calculate the start and end positions of the match
                    size_t start = (pos1 == data.find("!!") ? (pos1 + 2) : (pos1 + 4)); // Skip 2 characters if no spaces between characters were found, 4 otherwise
                    size_t endPos = pos2 + ((pos2 == data.find(searchStringWithSpaces, pos1)) ? 7 : 4);

                    /**
                     *
                     * This code block checks if a DPS string with a correct format was found to avoid false flagging corrupt data.
                     * I will take !!svchost.exe!2092/10/12:19:58:29! as an example to explain this part of the code.
                     * Each character is checked. For example, a DPS string will always have a digit in the first position after ".exe!" or ". e x e !".
                     * We can analyze if at a certain bit of the string, there is a digit, a colon, a slash, etc... to check if a DPS string was found.
                     *
                    */

                    bool CorrectFormat = false;
                    if (endPos < data.length() - 20) {
                        char c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20;

                        if (pos2 == data.find(searchStringWithSpaces, pos1)) {
                            // If ". e x e !" was found, a DPS string with spaces between characters was found.
                            // Therefore we will have to skip spaces between characters
                            c1 = data[endPos + 2]; // 2
                            c2 = data[endPos + 4]; // 0
                            c3 = data[endPos + 6]; // 9
                            c4 = data[endPos + 8]; // 2
                            c5 = data[endPos + 10]; // /
                            c6 = data[endPos + 12]; // 1
                            c7 = data[endPos + 14]; // 0
                            c8 = data[endPos + 16]; // / 
                            c9 = data[endPos + 18]; // 1
                            c10 = data[endPos + 20]; // 2
                            c11 = data[endPos + 22]; // :
                            c12 = data[endPos + 24]; // 1
                            c13 = data[endPos + 26]; // 9
                            c14 = data[endPos + 28]; // :
                            c15 = data[endPos + 30]; // 5
                            c16 = data[endPos + 32]; // 8
                            c17 = data[endPos + 34]; // :
                            c18 = data[endPos + 36]; // 2
                            c19 = data[endPos + 38]; // 9
                            c20 = data[endPos + 40]; // !
                        }
                        else {
                            // If ".exe!" was found, use normal positions since there are no spaces between characters to skip
                            c1 = data[endPos + 1]; // 2
                            c2 = data[endPos + 2]; // 0
                            c3 = data[endPos + 3]; // 9
                            c4 = data[endPos + 4]; // 2
                            c5 = data[endPos + 5]; // /
                            c6 = data[endPos + 6]; // 1
                            c7 = data[endPos + 7]; // 0
                            c8 = data[endPos + 8]; // / 
                            c9 = data[endPos + 9]; // 1
                            c10 = data[endPos + 10]; // 2
                            c11 = data[endPos + 11]; // :
                            c12 = data[endPos + 12]; // 1
                            c13 = data[endPos + 13]; // 9
                            c14 = data[endPos + 14]; // :
                            c15 = data[endPos + 15]; // 5
                            c16 = data[endPos + 16]; // 8
                            c17 = data[endPos + 17]; // :
                            c18 = data[endPos + 18]; // 2
                            c19 = data[endPos + 19]; // 9
                            c20 = data[endPos + 20]; // !
                        }
                        // Check if the characters at these positions are digits and the last character is a slash
                        if (isdigit(c1) && isdigit(c2) && isdigit(c3) && isdigit(c4) && c5 == '/'
                            && isdigit(c6) && isdigit(c7) && c8 == '/' && isdigit(c9) && isdigit(c10)
                            && c11 == ':' && isdigit(c12) && isdigit(c13) && c14 == ':' && isdigit(c15)
                            && isdigit(c16) && c17 == ':' && isdigit(c18) && isdigit(c19) && c20 == '!') {
                            CorrectFormat = true;
                        }
                    }

                    // If a DPS string format was found succesfully:
                    if (CorrectFormat) {
                        std::string match = data.substr(start, endPos - start); // We extract the executable name
                        // Process the extracted string
                        ProcessMatchingString(match, printedMatches, outputChoice, output);
                    }
                }
            }

            pos1 = data.find("\\??\\");
            if (pos1 != std::string::npos) {
                pos1 += 4; // Move past \\??\\ //
                auto dataSubstring = data.substr(pos1);

                // Check if the substring has at least 3 characters (letter, colon, slash)
                if (dataSubstring.size() >= 3 && std::isalpha(dataSubstring[0]) && dataSubstring[1] == ':' && dataSubstring[2] == '/') {
                    auto it = std::search(dataSubstring.begin(), dataSubstring.end(), ".exe", ".exe" + 4, // Increment +4 here to include the ".exe" extension.
                        [](char a, char b) {
                            return std::tolower(a) == std::tolower(b);
                        });

                    if (it != dataSubstring.end()) {
                        pos2 = pos1 + static_cast<size_t>(std::distance(dataSubstring.begin(), it));
                        std::string match = data.substr(pos1 + 4, pos2 - pos1); // Increment +4 here to include the ".exe" extension
                        ProcessMatchingString(match, printedMatches, outputChoice, output);
                    }
                }
            }

            // Handle the "java -jar" pattern
            pos1 = data.find("java -jar");
            if (pos1 != std::string::npos) {
                pos1 += 9; // Move past "java -jar"
                auto dataSubstring = data.substr(pos1);

                // Check if the first character in dataSubstring is an alphabetic character
                if (dataSubstring.size() > 0 && std::isalpha(dataSubstring[0])) {
                    auto it = std::search(dataSubstring.begin(), dataSubstring.end(), ".jar", ".jar" + 4, // Increment +4 here to include the ".exe" extension.
                        [](char a, char b) {
                            return ConvertToLowercase(a) == ConvertToLowercase(b);
                        });

                    if (it != dataSubstring.end()) {
                        pos2 = pos1 + static_cast<size_t>(std::distance(dataSubstring.begin(), it));
                        std::string match = data.substr(pos1 + 10, pos2 - pos1 - 10 + 4); // Increment +10 here to skip the "java -jar" command argument
                        ProcessMatchingString(match, printedMatches, outputChoice, output);
                    }
                }
            }

            // Store the last part of data (220 characters) for overlap with the next chunk.
            // This ensures that any partial information at the end of the chunk is retained for the next iteration.
            overlapData = data.substr(data.size() - 220);
        }
        else {
            done = true;
        }
    }

    std::vector<std::string> nonDeletedFiles;

    // Check if any printed matches correspond to non-existing files and print a message
    for (const std::string& printedMatch : printedMatches) {
        if (std::isalpha(printedMatch[0]) && printedMatch.size() >= 3 &&
            printedMatch[1] == ':' && printedMatch[2] == '\\') {
            if (!std::ifstream(printedMatch)) {
                if (outputChoice == 'C' || outputChoice == 'c') {
                    SET_TEXT_COLOR_RED(); // Set text color to red
                    std::cout << "Deleted file (file could not be found): ";
                    RESET_TEXT_COLOR(); // Reset text color so that the match is printed in white
                    std::cout << printedMatch << std::endl;
                }
                else if (outputChoice == 'F' || outputChoice == 'f') {
                    (*output) << "Deleted file (file could not be found): " << printedMatch << std::endl;
                }
            }
            else {
                nonDeletedFiles.push_back(printedMatch); // Store non-deleted files
            }
        }
    }

    TrustVerifyWrapper wrapper;
    std::set<std::wstring> unsignedFiles;

    // Iterate through non-deleted files and check for digital signatures
    for (const std::string& nonDeletedFile : nonDeletedFiles) {
        std::wstring wideFilePath(nonDeletedFile.begin(), nonDeletedFile.end());
        if (!wrapper.VerifyFileSignature(wideFilePath)) {
            SET_TEXT_COLOR_YELLOW(); // Set text color to yellow
            std::wcout << L"Unsigned file detected: " << std::endl;
            RESET_TEXT_COLOR(); // Reset text color so that the match is printed in white
            std::wcout << wideFilePath << std::endl;
            unsignedFiles.insert(wideFilePath);
        }
    }

    // Close the input file
    file.close();

    std::cout << "RAM scan finished." << std::endl;

    if (InstallMouseHook() && InstallKeyboardHook()) {
        MSG msg;
        while (!GetAsyncKeyState(VK_DELETE)) {
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }

        UninstallMouseHook();
        UninstallKeyboardHook();
    }

    return 0;
}
