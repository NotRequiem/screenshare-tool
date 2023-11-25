#include "keyboardhook.h"

// Global variable to store the keyboard hook
HHOOK hKeyboardHook;

// Structure to store data for each key
struct KeyData {
    int keyDownCount;
    int keyUpCount;
    DWORD lastKeyDownTime;
    DWORD lastKeyUpTime;
    DWORD lastKeyUpToKeyDownDelay;
    DWORD lastKeyDownToKeyUpDelay;
};

// Array to store KeyData for each virtual key code (0-255)
struct KeyData keyDataMap[256] = { 0 };

// Callback function for the low-level keyboard hook
static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;

    // Check if the hook should process the message
    if (nCode == HC_ACTION && !(p->flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED))) {
        DWORD currentTime = (DWORD)GetTickCount64();

        // Get the KeyData structure for the current virtual key code
        struct KeyData* keyData = &keyDataMap[p->vkCode];

        // Check if it's a keydown event
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            // Detect autoclicker by checking for 0ms delay between keydown events
            if (keyData->keyDownCount > 0 && (currentTime - keyData->lastKeyDownTime == 0)) {
                printf("Autoclicker detected: Key Down with 0ms delay. VK Code = %d, Delay = %I64ums\n", p->vkCode, (ULONGLONG)(currentTime - keyData->lastKeyDownTime));
            }
            keyData->keyDownCount++;
            keyData->lastKeyDownTime = currentTime;
        }
        // Check if it's a keyup event
        else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
            // Detect autoclicker by checking for 0ms delay between keyup events
            if (keyData->keyUpCount > 0 && (currentTime - keyData->lastKeyUpTime == 0)) {
                printf("Autoclicker detected: Key Up with 0ms delay. VK Code = %d, Delay = %I64ums\n", p->vkCode, (ULONGLONG)(currentTime - keyData->lastKeyUpTime));
            }
            keyData->keyUpCount++;
            keyData->lastKeyUpTime = currentTime;
        }
    } else {
        // Print a message if an injected keyboard event is detected
        printf("Autoclicker detected: Injected keyboard event was triggered.\n");
    }

    // Call the next hook in the chain
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

// Function to install the keyboard hook
bool InstallKeyboardHook() {
    // Set the low-level keyboard hook
    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardProc, GetModuleHandle(NULL), 0);

    // Check if the hook installation was successful
    if (!hKeyboardHook) {
        printf("Error installing keyboard hook. Error code: %d\n", GetLastError());
        UninstallKeyboardHook();
        return false;
    }

    return true;
}

// Function to uninstall the keyboard hook
void UninstallKeyboardHook() {
    // Check if the hook is installed
    if (hKeyboardHook != NULL) {
        // Unhook the keyboard hook
        if (!UnhookWindowsHookEx(hKeyboardHook)) {
            printf("Error uninstalling keyboard hook. Error code: %d\n", GetLastError());
        }
        // Set the hook variable to NULL
        hKeyboardHook = NULL;
    }
}
