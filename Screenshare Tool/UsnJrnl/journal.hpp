#ifndef JOURNAL_H
#define JOURNAL_H

#include <Windows.h>
#include <vector>
#include <string>

std::vector<std::wstring> GetDriveLetters();
void CheckDriveJournal(const std::wstring& driveLetter);

#endif
