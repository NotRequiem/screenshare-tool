#pragma once

#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <filesystem>
#include <unordered_set>

#include "..\..\miscellaneous\files\filetracker.hpp"
#include "..\..\miscellaneous\digital signature\trustverify.hpp"
#include "..\..\miscellaneous\gui\color.h"

const int MAX_LINE_LENGTH = 400;

void csrss(bool imp);
