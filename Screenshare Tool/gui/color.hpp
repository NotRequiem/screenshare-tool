#ifndef CONSOLE_COLOR_H
#define CONSOLE_COLOR_H

#include <iostream>
#include <windows.h>

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

class Console {
public:
    static void SetColor(ConsoleColor text, ConsoleColor background) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<int>(text) | (static_cast<int>(background) << 4));
    }

    static void ResetColor() {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<int>(ConsoleColor::White) | (static_cast<int>(ConsoleColor::Black) << 4));
    }
};

#endif
