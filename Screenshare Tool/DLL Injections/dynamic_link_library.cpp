#include "dynamic_link_library.hpp"
#include "Digital Signature\TrustVerifyWrapper.hpp"

bool IsFileOnFatDrive(const std::wstring& filePath) {
    WCHAR fileSystemName[MAX_PATH];
    DWORD fileSystemFlags;

    if (GetVolumeInformation(
        filePath.c_str(),
        nullptr, 0, nullptr,
        nullptr, &fileSystemFlags,
        fileSystemName, MAX_PATH))
    {
        return _wcsicmp(fileSystemName, L"FAT") == 0 || _wcsicmp(fileSystemName, L"FAT32") == 0;
    }

    return false;
}

bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}

void ScanDllFiles(const std::wstring& drive) {
    std::wcout << L"Scanning DLL files on drive: " << drive << std::endl;

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((drive + L"\\*.dll").c_str(), &findFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            const std::wstring filePath = drive + L"\\" + findFileData.cFileName;

            if (IsFileOnFatDrive(filePath)) {
                // Check if the DLL file has a valid digital signature
                if (!IsFileSignatureValid(filePath)) {
                    std::wcout << L"The program couldnt detect if this unsigned DLL file was injected into the system because it's inside a FAT drive: " << filePath << std::endl;
                }
            }
        } while (FindNextFile(hFind, &findFileData) != 0);

        FindClose(hFind);
    } else {
        std::wcerr << L"Error scanning for DLL injections on drive: " << drive << std::endl;
    }
}

void DetectUnsignedDLLs() {
    // Iterate over available drives
    for (int drive = 2; drive <= 26; ++drive) {
        TCHAR rootPath[4] = { static_cast<TCHAR>('A' + drive - 1), L':', L'\\', L'\0' };
        UINT driveType = GetDriveType(rootPath);

        if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
            // Check if the drive is formatted as FAT
            ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
            if (GetDiskFreeSpaceEx(rootPath, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
                if (totalNumberOfBytes.QuadPart > 0 && totalNumberOfFreeBytes.QuadPart > 0 &&
                    freeBytesAvailable.QuadPart * 100 / totalNumberOfBytes.QuadPart > 50) {
                    ScanDllFiles(rootPath);
                }
            }
        }
    }
}
