#ifndef CSRSS_H
#define CSRSS_H

#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <cwctype>

class CsrssCheck {
public:
    static void csrss();

private:
    static bool IsFileSignatureValid(const std::wstring& filePath);
    static bool CaseInsensitiveCompare(const std::wstring& str1, const std::wstring& str2);
};

#endif