#include "query.h"

bool IsTextFileEmpty(const TCHAR* filename) {
    FILE* file = _tfopen(filename, _T("r"));

    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fclose(file);

        if (size == 0) {
            // File is empty, remove it
            if (remove(filename) != 0) {
                // Unable to remove the file
                return false;
            }
        }
        return true;
    }

    // File not found or cannot be opened
    return false;
}

void RunCommand(TCHAR driveLetter) {
    TCHAR command[MAX_PATH] = { 0 };

    // Run fsutil usn readjournal and filter for old renamed files
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /c:0x00001000 >> old_renamed_files.txt"), driveLetter);
    system(command);

    // Run fsutil usn readjournal and filter for new renamed files
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /c:0x00002000 >> new_renamed_files.txt"), driveLetter);
    system(command);

    // Run fsutil usn readjournal and filter for special characters
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\"?\" >> special_characters.txt"), driveLetter);
    system(command);

    // Run fsutil usn readjournal and filter for glorious macros
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".mcf\" >> glorious.txt"), driveLetter);
    system(command);

    // Run fsutil usn readjournal and filter for logitech macros
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\"settings\\.db\" >> logitech.txt"), driveLetter);
    system(command);

    // Run fsutil usn readjournal and filter for bloody macros
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".amc2\" >> bloody.txt"), driveLetter);
    system(command);
    
    // Run fsutil usn readjournal and filter for corsair macros
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\".cuecfg\" >> corsair.txt"), driveLetter);
    system(command);

    IsTextFileEmpty(_T("old_renamed_files.txt"));
    IsTextFileEmpty(_T("new_renamed_files.txt"));
    IsTextFileEmpty(_T("special_characters.txt"));
    IsTextFileEmpty(_T("glorious.txt"));
    IsTextFileEmpty(_T("logitech.txt"));
    IsTextFileEmpty(_T("bloody.txt"));
    IsTextFileEmpty(_T("corsair.txt"));
}