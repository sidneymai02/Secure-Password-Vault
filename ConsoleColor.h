#pragma once
#include <windows.h>

enum class ConsoleColor {
    DEFAULT = 7,      // Light gray
    RED = 12,
    GREEN = 10,
    YELLOW = 14,
    CYAN = 11,
    MAGENTA = 13
};

inline void setConsoleColor(ConsoleColor color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
}

inline void resetConsoleColor() {
    setConsoleColor(ConsoleColor::DEFAULT);
}