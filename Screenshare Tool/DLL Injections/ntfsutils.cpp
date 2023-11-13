#include "ntfsutils.hpp"

bool isNTFSDrive(const std::wstring& drive) {
    DWORD fileSystemFlags;
    if (GetVolumeInformationW(drive.c_str(), NULL, 0, NULL, NULL, &fileSystemFlags, NULL, 0)) {
        return (fileSystemFlags & FILE_SUPPORTS_USN_JOURNAL);
    }
    return false;
}

void runMFTECmd(const std::wstring& mfteCmdPath, const std::wstring& arguments, const std::wstring& drive) {
    std::wstring command = mfteCmdPath + L" " + arguments;
    size_t pos = command.find(L"<drive>");
    if (pos != std::wstring::npos) {
        command.replace(pos, 7, drive);

        wprintf(L"Parsing $MFT: %s\n", command.c_str());

        const wchar_t* commandStr = command.c_str();

        _wsystem(commandStr);
    }
}

std::vector<std::wstring> getNTFSDrives() {
    std::vector<std::wstring> drives;
    DWORD drivesSize = GetLogicalDriveStringsW(0, NULL);

    if (drivesSize > 0) {
        std::vector<wchar_t> driveLetters(drivesSize + 1);
        if (GetLogicalDriveStringsW(drivesSize, &driveLetters[0])) {
            for (size_t i = 0; i < drivesSize; i += 4) {
                std::wstring drive = std::wstring(&driveLetters[i], 3);
                if (isNTFSDrive(drive)) {
                    drives.push_back(drive);
                }
            }
        }
    }
    return drives;
}
