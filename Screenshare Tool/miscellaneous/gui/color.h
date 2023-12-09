#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Enumeration for text colors
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
        BrightWhite,

        // Additional colors
        DarkGray = 8,
        DarkBlue,
        DarkGreen,
        DarkCyan,
        DarkRed,
        DarkMagenta,
        DarkYellow,
        LightGray,
        LightBlue,
        LightGreen,
        LightCyan,
        LightRed,
        LightMagenta,
        LightYellow,
        LightWhite
    };

    // Function prototypes to include color in the ss tool
    void setConsoleTextColor(enum ConsoleColor textColor);
    void resetConsoleTextColor();

#ifdef __cplusplus
}
#endif