#include "localhost.h"

void LocalHost() {
    DWORD dwEntriesRead = 0;
    NETRESOURCE* lpNetResource = NULL;
    HANDLE hEnum;

    if (WNetOpenEnum(RESOURCE_GLOBALNET, RESOURCETYPE_ANY, 0, NULL, &hEnum) != NO_ERROR) {
        perror("WNetOpenEnum");
        return; // Unable to open the network enumeration, so just return
    }

    do {
        DWORD dwBufferSize = 16384;
        lpNetResource = (NETRESOURCE*)malloc(dwBufferSize);

        if (lpNetResource == NULL) {
            perror("malloc");
            return; // Unable to allocate memory, so just return
        }

        if (WNetEnumResource(hEnum, &dwEntriesRead, lpNetResource, &dwBufferSize) == NO_ERROR) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (lpNetResource[i].lpRemoteName != NULL) {
                    size_t len = strlen(lpNetResource[i].lpRemoteName) + 1;
                    wchar_t* wideRemoteName = (wchar_t*)malloc(len * sizeof(wchar_t));
                    MultiByteToWideChar(CP_ACP, 0, lpNetResource[i].lpRemoteName, -1, wideRemoteName, (int)len);

                    if (_wcsnicmp(wideRemoteName, L"\\\\", 2) == 0) {
                        wprintf(L"Found network share: %s. Check if there are cheats on this drive.\n", (wchar_t*)lpNetResource[i].lpRemoteName);

                        printf("Drive(s): ");
                        DWORD dwDrives = GetLogicalDrives();
                        for (WCHAR drive = 0; drive < 26; drive++) {
                            if (dwDrives & (1 << drive)) {
                                WCHAR remoteName[MAX_PATH];
                                WCHAR wideDriveLetter[4];
                                swprintf(wideDriveLetter, sizeof(wideDriveLetter) / sizeof(wideDriveLetter[0]), L"%c:\\", 'A' + drive);

                                DWORD bufferSize = MAX_PATH;

                                if (WNetGetConnectionW(wideDriveLetter, remoteName, &bufferSize) == NO_ERROR) {
                                    char narrowRemoteName[MAX_PATH];
                                    WideCharToMultiByte(CP_ACP, 0, remoteName, -1, narrowRemoteName, sizeof(narrowRemoteName), NULL, NULL);
                                    wprintf(L"%c: ", 'A' + drive);
                                }
                            }
                        }

                        printf("\n");

                        free(wideRemoteName);
                        free(lpNetResource);

                        if (WNetCloseEnum(hEnum) != NO_ERROR) {
                            perror("WNetCloseEnum");
                        }

                        return; // Found a network share, so just return
                    }

                    free(wideRemoteName);
                }
            }
        }
        else {
            perror("WNetEnumResource");
            free(lpNetResource);

            if (WNetCloseEnum(hEnum) != NO_ERROR) {
                perror("WNetCloseEnum");
            }

            return; // Unable to enumerate resources, so just return
        }

        free(lpNetResource);
        lpNetResource = NULL;
    } while (dwEntriesRead > 0);

    if (WNetCloseEnum(hEnum) != NO_ERROR) {
        perror("WNetCloseEnum");
        return; // Error closing enumeration, so just return
    }

    // No network share found, finish the function (no return statement here since it's a void function)
}
