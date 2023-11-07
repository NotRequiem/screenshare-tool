#include "StringProcessing.hpp"
#include "FilePathMapping.hpp"
#include "ConsoleOutput.hpp"

// Function to process and clean up strings to be printed
void CleanStringForPrinting(std::string& inputString) {
    size_t length = inputString.size();
    size_t writeIndex = 0;
    for (size_t readIndex = 0; readIndex < length; ++readIndex) {
        char currentChar = inputString[readIndex];
        switch (currentChar) {
        case '%':
            if (readIndex + 2 < length) {
                switch (inputString[readIndex + 1]) {
                case '3':
                    if (inputString[readIndex + 2] == 'A') {
                        currentChar = ':';
                        readIndex += 2;
                    }
                    break;
                case '0':
                    currentChar = ' ';
                    readIndex += 2;
                    break;
                case '8':
                    currentChar = '(';
                    readIndex += 2;
                    break;
                case '9':
                    currentChar = ')';
                    readIndex += 2;
                    break;
                }
            }
            break;
        case '/':
            currentChar = '\\';
            break;
        }
        if ((currentChar >= 32 && currentChar <= 126) && !std::isspace(currentChar)) {
            inputString[writeIndex] = currentChar;
            ++writeIndex;
        }
    }
    inputString.resize(writeIndex);
}

// Function to process the memory image file
void ProcessMatchingString(std::string& match, std::unordered_set<std::string>& printedMatches, char outputChoice, std::unique_ptr<std::ostream>& output) {
    // Check if the match contains "HarddiskVolume" and replace it with the drive letter
    if (match.find("HarddiskVolume") != std::string::npos) {
        std::map<std::wstring, std::wstring> dosPathDevicePathMap = GetDosPathDevicePathMap();
        size_t pos = match.find("\\\\Device\\\\HarddiskVolume");
        if (pos != std::string::npos) {
            // Find the position of the numeric part
            size_t start = pos + 24;
            size_t end = start;
            while (end < match.length() && std::isdigit(match[end])) {
                end++;
            }

            // Extract the numeric part
            std::string volumePart = match.substr(start, end - start);

            // Trim and sanitize the extracted numeric part
            volumePart.erase(std::remove_if(volumePart.begin(), volumePart.end(), [](char c) { return !std::isdigit(c); }), volumePart.end());

            // Check if volumePart is a valid integer
            if (!volumePart.empty()) {
                int volNum = std::stoi(volumePart); // Convert the numeric part to an integer

                // Find the corresponding drive letter
                wchar_t driveLetter = 0;
                for (const auto& entry : dosPathDevicePathMap) {
                    if (entry.second.find(L"HarddiskVolume" + std::to_wstring(volNum)) != std::wstring::npos) {
                        driveLetter = entry.first[0];
                        break;
                    }
                }

                // Replace the numeric part of the device path with the correct drive letter and a colon
                if (driveLetter != 0) {
                    std::string replacement = std::string(1, static_cast<char>(driveLetter)) + ":";
                    match.replace(pos, end - pos, replacement);
                }
            }
        }
    }

    // Replace double backslashes with a single backslash.
    size_t doubleBackslashPos = match.find("\\\\");
    while (doubleBackslashPos != std::string::npos) {
        match.replace(doubleBackslashPos, 2, "\\");
        doubleBackslashPos = match.find("\\\\", doubleBackslashPos + 1);
    }


    // Check if the match contains "ProgramFiles" and replace it with a more human-readable format
    if (match.find("ProgramFiles(x86)") != std::string::npos) {
        size_t pos = match.find("ProgramFiles(x86)");
        match.replace(pos, 17, "Program Files (x86)");
    }
    else if (match.find("ProgramFiles") != std::string::npos) {
        size_t pos = match.find("ProgramFiles");
        match.replace(pos, 12, "Program Files");
    }

    if (match.find("file:///") != std::string::npos) {

        // Remove "file:///" prefix (first 8 characters)
        match = match.substr(8);
        CleanStringForPrinting(match); // Clean up the string further

        // Convert the match to lowercase for case-insensitive comparison
        std::string lowercaseMatch = match;
        std::transform(lowercaseMatch.begin(), lowercaseMatch.end(), lowercaseMatch.begin(), ::tolower);

        if (printedMatches.find(lowercaseMatch) == printedMatches.end() && match.length() <= 110 && match.length() > 4) {
            printedMatches.insert(lowercaseMatch); // Insert the lowercase match into the set to keep track of it

            // Print the modified match in the desired output.
            if (outputChoice == 'C' || outputChoice == 'c') {
                SET_TEXT_COLOR_GREEN(); // Set text color to green
                std::cout << "Accessed file: ";
                RESET_TEXT_COLOR(); // Reset text color
                std::cout << match << std::endl;
            }
            else if (outputChoice == 'F' || outputChoice == 'f') {
                (*output) << "Accessed file: " << match << std::endl;
            }
        }
    }

    CleanStringForPrinting(match); // Clean up the string further

    // Convert the match to lowercase for case-insensitive comparison
    std::string lowercaseMatch = match;
    std::transform(lowercaseMatch.begin(), lowercaseMatch.end(), lowercaseMatch.begin(), ::tolower);

    // Check if the lowercase match has not been previously printed and meets the length condition
    if (printedMatches.find(lowercaseMatch) == printedMatches.end() && match.length() <= 110 && match.length() > 4) {
        // Insert the lowercase match into the set to keep track of it
        printedMatches.insert(lowercaseMatch);

        // Print the original match in the desired output
        if (outputChoice == 'C' || outputChoice == 'c') {
            SET_TEXT_COLOR_BLUE(); // Set text color to blue
            std::cout << "Executed file: ";
            RESET_TEXT_COLOR(); // Reset text color so that the match is printed in white
            std::cout << match << std::endl;
        }
        else if (outputChoice == 'F' || outputChoice == 'f') {
            (*output) << "Executed file: " << match << std::endl;
        }
    }
}