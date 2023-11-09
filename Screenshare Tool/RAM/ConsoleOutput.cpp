#include "ConsoleOutput.hpp"
#include <array>

std::array<char, 256> lowercaseConversionTable;

// Text colors for console output
#ifdef _WIN32
#define SET_TEXT_COLOR_BLUE() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9)
#define SET_TEXT_COLOR_GREEN() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10)
#define SET_TEXT_COLOR_RED() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12)
#define SET_TEXT_COLOR_YELLOW() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14)
#define RESET_TEXT_COLOR() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7)
#endif

// Function to initialize the lowercaseConversionTable array
void InitializeLowercaseConversionTable() {
    for (int i = 0; i < 256; ++i) {
        lowercaseConversionTable[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(i)));
    }
}

// Function to convert a character to lowercase using the lowercaseConversionTable
char ConvertToLowercase(char character) {
    // Ensure that the character is within the valid range (0-255)
    if (character >= 0 && character <= 255) {
        return lowercaseConversionTable[static_cast<unsigned char>(character)];
    }
    else {
        // Return the character as is if it's out of bounds
        return character;
    }
}