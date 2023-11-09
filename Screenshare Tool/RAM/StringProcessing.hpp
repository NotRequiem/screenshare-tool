#pragma once

#include <string>
#include <unordered_set>
#include <iostream>
#include <algorithm>

constexpr size_t MIN_CHUNK_SIZE = 330; // Read the ram memory in file chunks

void CleanStringForPrinting(std::string& inputString);
void ProcessMatchingString(std::string& match, std::unordered_set<std::string>& printedMatches, char outputChoice, std::unique_ptr<std::ostream>& output);
