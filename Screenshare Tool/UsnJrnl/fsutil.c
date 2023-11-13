#include "file_util.h"
#include "query.h"
#include "fsutil.h"

// Function to check if a drive is NTFS
bool IsNTFSDrive(TCHAR driveLetter) {
    TCHAR rootPath[4] = { driveLetter, _T(':'), _T('\\'), _T('\0') };
    DWORD fileSystemFlags;
    if (GetVolumeInformation(rootPath, NULL, 0, NULL, NULL, &fileSystemFlags, NULL, 0)) {
        return (fileSystemFlags & FILE_SUPPORTS_SPARSE_FILES) != 0;
    }
    return false;
}

// Function to iterate through all drives and call RunCommand for NTFS drives
void IterateAndRunCommand() {
    DWORD drives = GetLogicalDrives();
    TCHAR driveLetter = 'A';

    while (drives) {
        if (drives & 1) {
            if (GetDriveType(driveLetter) == DRIVE_FIXED && IsNTFSDrive(driveLetter)) {
                RunCommand(driveLetter);
            }
        }
        drives >>= 1;
        ++driveLetter;
    }
}

void ReplacedFiles() {
    TCHAR desktopPath[MAX_PATH];
    if (SHGetSpecialFolderPath(0, desktopPath, CSIDL_DESKTOP, 0) == S_OK) {
        TCHAR usnJournalPath[MAX_PATH];
        _stprintf(usnJournalPath, _T("%s\\UsnJournal"), desktopPath);
        CreateDirectory(usnJournalPath, NULL);

        TCHAR oldFile[MAX_PATH];
        _stprintf(oldFile, _T("%s\\old_file_names.txt"), usnJournalPath);

        TCHAR newFile[MAX_PATH];
        _stprintf(newFile, _T("%s\\new_file_names.txt"), usnJournalPath);

        TCHAR resultFile[MAX_PATH];
        _stprintf(resultFile, _T("%s\\replaced_files.txt"), usnJournalPath);

        IterateAndRunCommand();

        CompareFilesAndWriteResult(oldFile, newFile, resultFile);

        _stprintf(usnJournalPath, _T("%s\\UsnJournal"), desktopPath);
        ShellExecute(NULL, _T("open"), usnJournalPath, NULL, NULL, SW_SHOWNORMAL);

        DeleteFile(oldFile);
        DeleteFile(newFile);
    }
}
