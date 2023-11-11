#include "query.h"

void RunCommand(TCHAR driveLetter) {
    TCHAR command[MAX_PATH] = { 0 };

    // Run fsutil usn readjournal and filter for 0x00001000
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /c:0x00001000 >> old_renamed_files.txt"), driveLetter);
    system(command);

    // Run fsutil usn readjournal and filter for 0x00002000
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /c:0x00002000 >> new_renamed_files.txt"), driveLetter);
    system(command);

    // Run fsutil usn readjournal and filter for special characters
    _stprintf(command, _T("fsutil usn readjournal %c: csv | findstr /i /C:\"?\" >> special_characters.txt"), driveLetter);
    system(command);
}


