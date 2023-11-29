#ifndef CONSOLE_COLOR_H
#define CONSOLE_COLOR_H

#include <iostream>
#include <windows.h>

// Enum to represent console text and background colors
enum class ConsoleColor {
    Black = 0,
    Blue,
    Green,
    Cyan,
    Red,
    Magenta,
    Yellow,
    White,
    Gray,
    BrightBlue,
    BrightGreen,
    BrightCyan,
    BrightRed,
    BrightMagenta,
    BrightYellow,
    BrightWhite
};

// Console class with static methods for setting and resetting console colors
class Console {
public:
    // Set the console text and background color
    static void SetColor(ConsoleColor text, ConsoleColor background) {
        // Use SetConsoleTextAttribute to set the color attributes
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<int>(text) | (static_cast<int>(background) << 4));
    }

    // Reset the console text and background color to default (white text on black background)
    static void ResetColor() {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<int>(ConsoleColor::White) | (static_cast<int>(ConsoleColor::Black) << 4));
    }
};

#endif
