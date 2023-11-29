#ifndef CONSOLE_COLOR_H
#define CONSOLE_COLOR_H

#include <windows.h>

// Enumeration for text and background colors
enum ConsoleColor {
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

// Function prototypes to include color in the ss tool
void setConsoleTextColor(enum ConsoleColor textColor, enum ConsoleColor backgroundColor);
void resetConsoleTextColor();

#endif
