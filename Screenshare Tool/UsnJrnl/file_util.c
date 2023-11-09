#include "file_util.h"

void CompareFilesAndWriteResult(const TCHAR* oldFilePath, const TCHAR* newFilePath, const TCHAR* resultFilePath) {
    FILE* oldFile = _tfopen(oldFilePath, _T("r"));
    if (oldFile == NULL) {
        _tprintf(_T("Failed to open file to detect file replaces in NTFS.\n"));
        return;
    }

    FILE* newFile = _tfopen(newFilePath, _T("r"));
    if (newFile == NULL) {
        _tprintf(_T("Failed to open file to detect file replaces in NTFS.\n"));
        fclose(oldFile);
        return;
    }

    FILE* resultFile = _tfopen(resultFilePath, _T("w"));
    if (resultFile == NULL) {
        _tprintf(_T("Failed to create result file with detected replaced files.\n"));
        fclose(oldFile);
        fclose(newFile);
        return;
    }

    TCHAR oldLine[2048];
    TCHAR newLine[2048];
    TCHAR* oldPath;
    TCHAR* oldTime;
    TCHAR* newPath;
    TCHAR* newTime;
    int matchedLines = 0;

   while (_fgetts(oldLine, sizeof(oldLine), oldFile) != NULL) {
    oldPath = _tcstok(oldLine, _T(","));
    oldTime = _tcstok(NULL, _T(",\n"));

    _fseek(newFile, 0, SEEK_SET);

        while (_fgetts(newLine, sizeof(newLine), newFile) != NULL) {
            newPath = _tcstok(newLine, _T(","));
            newTime = _tcstok(NULL, _T(",\n"));

            if (_tcscmp(oldPath, newPath) == 0 &&
                _tcscmp(oldTime, newTime) == 0 &&
                _tcsstr(oldTime, _T("\\d{1,2}/\\d{1,2}/\\d{4} \\d{1,2}:\\d{2}:\\d{2}") != NULL)) {
                    _ftprintf(resultFile, _T("%s,%s\n"), oldPath, oldTime);
                    _ftprintf(resultFile, _T("%s,%s\n"), newPath, newTime);
                    matchedLines++;
            }
        }
    }

    fclose(oldFile);
    fclose(newFile);
    fclose(resultFile);

    if (matchedLines > 0) {
        _tprintf(_T("Replaced files were exported to %s\\replaced_files.txt.\n"), resultFilePath);
    }
    else {
        _tprintf(_T("No replaced files in NTFS drives were detected.\n"));
    }
}