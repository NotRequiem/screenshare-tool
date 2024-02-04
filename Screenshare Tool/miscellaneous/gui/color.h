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

        // Additional foreground colors
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
        LightWhite,

        // Background colors
        BGBlack = 0x0000,
        BGBlue = 0x0010,
        BGGreen = 0x0020,
        BGCyan = 0x0030,
        BGRed = 0x0040,
        BGMagenta = 0x0050,
        BGYellow = 0x0060,
        BGWhite = 0x0070,
        BGGray = 0x0080,
        BGBrightBlue = 0x0090,
        BGBrightGreen = 0x00A0,
        BGBrightCyan = 0x00B0,
        BGBrightRed = 0x00C0,
        BGBrightMagenta = 0x00D0,
        BGBrightYellow = 0x00E0,
        BGBrightWhite = 0x00F0,
    };

    // Function prototypes to include color in the ss tool
    void setConsoleTextColor(enum ConsoleColor textColor);
    void resetConsoleTextColor();

#define FOREGROUND_RESET (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

#ifdef __cplusplus
}
#endif
