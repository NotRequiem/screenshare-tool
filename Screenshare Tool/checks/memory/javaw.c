#include "javaw.h"

static const char* cheatStrings[] = {
    "ReachCommands.class",
    "aimassist.class",
    "aimbot.class",
    "killaura.class",
    "triggerbot.class",
    "autopot.class",
    "bhop.class",
    "smoothaimbot.class",
    "nofall.class",
    "wallhack.class",
    "autoclick.class",
    "reach.class",
    "forcefield.class",
    "aimboat.class",
    "antivoid.class",
    "AimbotGui.class",
    "AutoSoup.class",
    "AutoPot.class",
    "Freecam.class",
    "NoSlowDown.class",
    "NoFall.class",
    "AntiFall.class",
    "Scaffold.block",
    "Player ESP.class",
    "BedFucker.class",
    "InvWalk.class",
    "FastEat.class",
    "ChestEsp.class",
    "ChestStealer.class",
    "InfinityJump.class",
    "AutoArmor.class",
    "MobAura.class",
    "BaseFinder.class",
    "FastBow.class",
    "Misplace.class",
    "FightBot.class",
    "AutoGap.class",
    "ChestAura.class",
    "AutoBlockhit.class",
    "SpawnerFinder.class",
    "Cavefinder.class",
    "StorageESP.class",
    "NametagsESP.class",
    "ItemESP.class",
    "NoClickDelay.class",
    "AutoRefill.class",
    "AutoPearl.class",
    "AutoEat.class",
    "airjump.class",
    "Lagback.class",
    "Backtrack.class",
    "TPAura_Attack.class",
    "_Velocity_Horizontal.class",
    "_Velocity_Vertical.class",
    "_Regen_Health_.class",
    "_NoFall_Mode_.class",
    "WaterSpeed.class",
    "AntiFire.class",
    "AimSpeed.class",
    "XRay.class",
    "EntityKiller.class",
    "Bhop.class",
    "CrystalAura.class",
    "clicker.class",
    "ReachCommands.java",
    "aimassist.java",
    "aimbot.java",
    "killaura.java",
    "triggerbot.java",
    "autopot.java",
    "bhop.java",
    "smoothaimbot.java",
    "nofall.java",
    "wallhack.java",
    "autoclick.java",
    "reach.java",
    "forcefield.java",
    "aimboat.java",
    "antivoid.java",
    "AimbotGui.java",
    "AutoSoup.java",
    "AutoPot.java",
    "Freecam.java",
    "NoSlowDown.java",
    "NoFall.java",
    "AntiFall.java",
    "Scaffold.block",
    "Player ESP.java",
    "BedFucker.java",
    "InvWalk.java",
    "FastEat.java",
    "ChestEsp.java",
    "ChestStealer.java",
    "InfinityJump.java",
    "AutoArmor.java",
    "MobAura.java",
    "BaseFinder.java",
    "FastBow.java",
    "Misplace.java",
    "FightBot.java",
    "AutoGap.java",
    "ChestAura.java",
    "AutoBlockhit.java",
    "SpawnerFinder.java",
    "Cavefinder.java",
    "StorageESP.java",
    "NametagsESP.java",
    "ItemESP.java",
    "NoClickDelay.java",
    "AutoRefill.java",
    "AutoPearl.java",
    "AutoEat.java",
    "airjump.java",
    "Lagback.java",
    "Backtrack.java",
    "TPAura_Attack.java",
    "_Velocity_Horizontal.java",
    "_Velocity_Vertical.java",
    "_Regen_Health_.java",
    "_NoFall_Mode_.java",
    "WaterSpeed.java",
    "AntiFire.java",
    "AimSpeed.java",
    "XRay.java",
    "EntityKiller.java",
    "Bhop.java",
    "CrystalAura.java",
    "clicker.java"
};

static void AnalyzeStrings(HANDLE hProcess) {
    SIZE_T bytesRead;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = 0;
    unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE);

    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        CloseHandle(hProcess);
        return;
    }

    size_t startIndex = 0;
    ULONGLONG startTime = GetTickCount64();

    __try {
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
            if ((mbi.State == MEM_COMMIT) &&
                (mbi.Type == MEM_PRIVATE) &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
                address = (unsigned char*)mbi.BaseAddress;

                if (ReadProcessMemory(hProcess, address, buffer, BUFFER_SIZE, &bytesRead)) {
                    for (size_t i = 0; i < bytesRead; i++) {
                        if (buffer[i] >= 32 && buffer[i] <= 126) {
                            continue;
                        }

                        if (i - startIndex >= MIN_STRING_LENGTH) {
                            for (size_t j = 0; j < sizeof(cheatStrings) / sizeof(cheatStrings[0]); j++) {
                                // Use StrStrI for case-insensitive substring matching
                                if (StrStrI((LPCSTR)&buffer[startIndex], cheatStrings[j]) != NULL) {
                                    wprintf(L"Cheating string detected in Minecraft process: %lu, ban the user.\n", GetProcessId(hProcess));
                                }
                            }
                        }

                        startIndex = i + 1;
                    }
                }

                address += bytesRead;
            }
            address += mbi.RegionSize;

            // Check for the timeout
            ULONGLONG elapsedTime = GetTickCount64() - startTime;
            if (elapsedTime > TIMEOUT_DURATION) {
                fprintf(stderr, "Timeout reached. Scanning took more than 10 seconds. Continuing...\n");
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "Exception caught during memory analysis.\n");
        free(buffer);
        CloseHandle(hProcess);
        return;
    }

    free(buffer);
    CloseHandle(hProcess);
}

void Javaw() {
    setConsoleTextColor(BrightYellow);
    wprintf(L"[Memory Scanner] Running checks to detect internal cheats in Minecraft's memory...\n");
    resetConsoleTextColor();

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error creating process snapshot.\n");
        return;
    }

    int processCount = 0; // Count the number of matching processes

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, "javaw.exe") == 0 || strcmp(pe32.szExeFile, "Minecraft.Windows.exe") == 0) {
                processCount++;

                if (processCount > 1) {
                    // Print a warning if more than one process is detected
                    wprintf(L"[#] Multiple processes detected. The scan might take a while.\n");
                }

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    // Call the function to analyze strings
                    AnalyzeStrings(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
}
