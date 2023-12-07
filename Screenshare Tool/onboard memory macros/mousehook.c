#include "mousehook.h"

HHOOK hMouseHook;

ULONG64 timeInterval;

int autoclickCountLeft = 0;
int autoclickCountRight = 0;
int autoclickCountMiddle = 0;
int autoclickCountXButton = 0;

ULONG64 previousIntervalLeft = 0;
ULONG64 previousIntervalRight = 0;
ULONG64 previousIntervalMiddle = 0;
ULONG64 previousIntervalXButton = 0;

ULONG64 downTimeLeft = 0;
ULONG64 upTimeLeft = 0;
ULONG64 timeIntervalLeft = 0;
ULONG64 lastUpTimeLeft = 0;

ULONG64 downTimeRight = 0;
ULONG64 upTimeRight = 0;
ULONG64 timeIntervalRight = 0;
ULONG64 lastUpTimeRight = 0;

ULONG64 downTimeMiddle = 0;
ULONG64 upTimeMiddle = 0;
ULONG64 timeIntervalMiddle = 0;
ULONG64 lastUpTimeMiddle = 0;

ULONG64 downTimeXButton = 0;
ULONG64 upTimeXButton = 0;
ULONG64 timeIntervalXButton = 0;
ULONG64 lastUpTimeXButton = 0;

static LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    MSLLHOOKSTRUCT* p = (MSLLHOOKSTRUCT*)lParam;

    if (nCode == HC_ACTION) {
        ULONG64 now = GetTickCount64();

        if (wParam == 513 || wParam == 515) { // Left mouse button is being clicked or double-clicked
            downTimeLeft = now;
        }

        if (wParam == 514) { // Left mouse button is being released
            upTimeLeft = now;
            if (upTimeLeft < downTimeLeft) {
                timeIntervalLeft = (ULLONG_MAX - downTimeLeft) + upTimeLeft + 1;
            } else {
                timeIntervalLeft = upTimeLeft - downTimeLeft;
            }

            if (timeIntervalLeft == 0) {
                printf("[!] Autoclicker detected in the left mouse button. Delay Press-To-Release is 0ms. Ban the user.\n");
            } else {
                printf("Left click detected.\n");

                if (autoclickCountLeft == 0) {
                    previousIntervalLeft = timeIntervalLeft;
                } else if (timeIntervalLeft != previousIntervalLeft) {
                    autoclickCountLeft = 0;
                }

                if (autoclickCountLeft >= 10) {
                    printf("[!] Left Mouse Button Autoclick detected (No Randomization): %llums delay. Ban the user.\n", timeIntervalLeft);
                }

                autoclickCountLeft++;
            }

            lastUpTimeLeft = upTimeLeft;
        }

        if ((wParam == 513 || wParam == 515) && lastUpTimeLeft != 0) { // Left mouse button is being pressed again
            timeInterval = downTimeLeft - lastUpTimeLeft;
            if (timeInterval == 0) {
                printf("[!] Autoclicker detected in the left mouse button. Delay Release-To-Press is 0ms. Ban the user.");
            }
        }

        if (wParam == 516 || wParam == 518) { // Right mouse button is being clicked or double-clicked
            downTimeRight = now;
        }

        if (wParam == 517) { // Right mouse button is being released
            upTimeRight = now;
            if (upTimeRight < downTimeRight) {
                timeIntervalRight = (ULLONG_MAX - downTimeRight) + upTimeRight + 1;
            } else {
                timeIntervalRight = upTimeRight - downTimeRight;
            }

            if (timeIntervalRight == 0) {
                printf("[!] Autoclicker detected in the right mouse button. Delay Press-To-Release is 0ms. Ban the user.\n");
            } else {
                printf("Right click detected.\n");

                if (autoclickCountRight == 0) {
                    previousIntervalRight = timeIntervalRight;
                } else if (timeIntervalRight != previousIntervalRight) {
                    autoclickCountRight = 0;
                }

                if (autoclickCountRight >= 10) {
                    printf("[!] Right Mouse Button Autoclick detected (No Randomization): %llums delay. Ban the user.\n", timeIntervalRight);
                }

                autoclickCountRight++;
            }

            lastUpTimeRight = upTimeRight;
        }

        if (wParam == 516 || wParam == 518 && lastUpTimeRight != 0) { // Right mouse button is being pressed again
            timeInterval = downTimeRight - lastUpTimeRight;
            if (timeInterval == 0) {
            printf("[!] Autoclicker detected in the right mouse button. Delay Release-To-Press is 0ms. Ban the user.\n");
            }
        }

        if (wParam == 519 || wParam == 521) { // Middle mouse button is being clicked or double-clicked
            downTimeMiddle = now;
        }

        if (wParam == 520) { // Middle mouse button is being released
            upTimeMiddle = now;
            if (upTimeMiddle < downTimeMiddle) {
                timeIntervalMiddle = (ULLONG_MAX - downTimeMiddle) + upTimeMiddle + 1;
            } else {
                timeIntervalMiddle = upTimeMiddle - downTimeMiddle;
            }

            if (timeIntervalMiddle == 0) {
                printf("[!] Autoclicker detected in the middle mouse button. Delay Press-To-Release is 0ms. Ban the user.\n");
            } else {
                printf("Middle click detected.\n");

                if (autoclickCountMiddle == 0) {
                    previousIntervalMiddle = timeIntervalMiddle;
                } else if (timeIntervalMiddle != previousIntervalMiddle) {
                    autoclickCountMiddle = 0;
                }

                if (autoclickCountMiddle >= 10) {
                    printf("[!] Middle Mouse Button Autoclick detected (No Randomization): %llums delay. Ban the user.\n", timeIntervalMiddle);
                }

                autoclickCountMiddle++;
            }

            lastUpTimeMiddle = upTimeMiddle;
        }

        if (wParam == 519 && lastUpTimeMiddle != 0) { // Middle mouse button is being pressed again
            timeInterval = downTimeMiddle - lastUpTimeMiddle;
            if (timeInterval == 0) {
            printf("[!] Autoclicker detected in the middle mouse button. Delay Release-To-Press is 0ms. Ban the user.\n");
            }
        }

        if (wParam == 523 || wParam == 525) { // Extended mouse button (XBUTTON1 or XBUTTON2) is being clicked or double-clicked
            downTimeXButton = now;
        }

        if (wParam == 524) { // Extended mouse button (XBUTTON1 or XBUTTON2) is being released
            upTimeXButton = now;
            if (upTimeXButton < downTimeXButton) {
                timeIntervalXButton = (ULLONG_MAX - downTimeXButton) + upTimeXButton + 1;
            } else {
                timeIntervalXButton = upTimeXButton - downTimeXButton;
            }

            if (timeIntervalXButton == 0) {
                printf("[!] Autoclicker detected in the extended mouse button. Delay Press-To-Release is 0ms. Ban the user.\n");
            } else {
                printf("Side button detected.\n");

                if (autoclickCountXButton == 0) {
                    previousIntervalXButton = timeIntervalXButton;
                } else if (timeIntervalXButton != previousIntervalXButton) {
                    autoclickCountXButton = 0;
                }

                if (autoclickCountXButton >= 10) {
                    printf("[!] Extended Mouse Button Autoclick detected (No Randomization): %llums delay. Ban the user.\n", timeIntervalXButton);
                }

                autoclickCountXButton++;
            }

            lastUpTimeXButton = upTimeXButton;
        }

        if (wParam == 523 || wParam == 525 && lastUpTimeXButton != 0) { // Extended mouse button is being pressed again
            timeInterval = downTimeXButton - lastUpTimeXButton;
            if (timeInterval == 0) {
            printf("[!] Autoclicker detected in the extended mouse button. Delay Release-To-Press is 0ms. Ban the user.\n");
            }
        }
    }

    return CallNextHookEx(hMouseHook, nCode, wParam, lParam);
}

bool InstallMouseHook() {
    hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, (HOOKPROC)LowLevelMouseProc, GetModuleHandle(NULL), 0);

    if (!hMouseHook) {
        UninstallMouseHook();
        return false;
    }

    setConsoleTextColor(BrightRed);    
    printf("[Onboard Memory Macro Scanner] Running onboard memory macro checks...");
    printf("[Onboard Memory Macro Scanner] Press the DELETE key to stop the checks for onboard macros at any time.\n");
    printf("[Onboard Memory Macro Scanner] Mouse and keyboard hooks installed successfully.\n");
    printf("[Onboard Memory Macro Scanner] If you click on the console, the hook may freeze and any click will not be detected. Click outside the console.\n");
    resetConsoleTextColor();

    printf("Ask the user to click only one time every button/key of their mice and keyboard. You have to see in the console the left click, middle click, right click and extended button click being detected.\n");
    printf("If you see that the console spams a lot of messages when the user only clicked a button one time, ban the user.\n");
    printf("If you see an \"Autoclicker detected\" message, ban the user.\n");

    return true;
}

void UninstallMouseHook() {
    if (hMouseHook != NULL) {
        if (!UnhookWindowsHookEx(hMouseHook)) {
            printf("Error uninstalling mouse hook. Error code: %d\n", GetLastError());
        }
        hMouseHook = NULL;
    }
}
