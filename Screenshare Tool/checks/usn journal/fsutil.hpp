#pragma once

#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <filesystem>

#include "..\..\miscellaneous\gui\color.h"

constexpr auto MAX_LINE_SIZE = 1024;

typedef struct {
    char time[MAX_LINE_SIZE];
    char fileName[MAX_LINE_SIZE];
} FileData;

void USNJournal();
