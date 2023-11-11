#include <Windows.h>
#include <stdio.h>
#include "KeyboardHook.h"

HHOOK hKeyboardHook;

struct KeyData {
    int keyDownCount;
    int keyUpCount;
    DWORD lastKeyDownTime;
    DWORD lastKeyUpTime;
    DWORD lastKeyUpToKeyDownDelay;
    DWORD lastKeyDownToKeyUpDelay;
};

struct KeyData keyDataMap[256] = {0};

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;

    if (nCode == HC_ACTION && !(p->flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED))) {
        DWORD currentTime = GetTickCount64();

        struct KeyData* keyData = &keyDataMap[p->vkCode];

        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            if (keyData->keyDownCount > 0 && (currentTime - keyData->lastKeyDownTime == 0)) {
                printf("Autoclicker detected: Key Down with 0ms delay. VK Code = %d, Delay = %dms\n", p->vkCode, currentTime - keyData->lastKeyDownTime);
            }
            keyData->keyDownCount++;
            keyData->lastKeyDownTime = currentTime;
        } else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
            if (keyData->keyUpCount > 0 && (currentTime - keyData->lastKeyUpTime == 0)) {
                printf("Autoclicker detected: Key Up with 0ms delay. VK Code = %d, Delay = %dms\n", p->vkCode, currentTime - keyData->lastKeyUpTime);
            }
            keyData->keyUpCount++;
            keyData->lastKeyUpTime = currentTime;
        }
    } else {
        printf("Autoclicker detected: Injected keyboard event was triggered.\n");
    }

    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

bool InstallKeyboardHook() {
    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardProc, GetModuleHandle(NULL), 0);

    if (!hKeyboardHook) {
        printf("Error installing keyboard hook. Error code: %d\n", GetLastError());
        UninstallMouseHook();
        UninstallKeyboardHook();
        return false;
    }

    printf("Keyboard hook installed successfully.\n");
    return true;
}

void UninstallKeyboardHook() {
    if (hKeyboardHook != NULL) {
        if (!UnhookWindowsHookEx(hKeyboardHook)) {
            printf("Error uninstalling keyboard hook. Error code: %d\n", GetLastError());
        }
        hKeyboardHook = NULL;
    }
}
