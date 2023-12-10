#include "color.h"

void setConsoleTextColor(enum ConsoleColor textColor) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, textColor);
}

void resetConsoleTextColor() {
    setConsoleTextColor(White);
}