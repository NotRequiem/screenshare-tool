#include "color.h"

// Function to set text and background color
void setConsoleTextColor(enum ConsoleColor textColor, enum ConsoleColor backgroundColor) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), textColor | (backgroundColor << 4));
}

// Function to reset text color to default
void resetConsoleTextColor() {
    setConsoleTextColor(White, Black);
}
