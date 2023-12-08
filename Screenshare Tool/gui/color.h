#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Enumeration for text colors only
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
    void setConsoleTextColor(enum ConsoleColor textColor);
    void resetConsoleTextColor();

#ifdef __cplusplus
}
#endif