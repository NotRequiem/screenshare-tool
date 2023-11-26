#include "..\gui\color.hpp"
#include "mouse.hpp"

// External function to check the number of connected mice
void MouseCheck() {
    Console::SetColor(ConsoleColor::BrightGreen, ConsoleColor::Black);
    std::wcout << "[Device Scanner] Checking if more than one mice is plugged... " << std::endl;
    Console::ResetColor();
    UINT numDevices = 0;

    // First call to get the number of devices
    if (GetRawInputDeviceList(nullptr, &numDevices, sizeof(RAWINPUTDEVICELIST)) == -1) {
        std::cerr << "Failed checking if more than one mice were plugged into the computer." << std::endl;
        return;
    }

    RAWINPUTDEVICELIST* rawInputDeviceList = new RAWINPUTDEVICELIST[numDevices];

    // Second call to get the actual device list
    if (GetRawInputDeviceList(rawInputDeviceList, &numDevices, sizeof(RAWINPUTDEVICELIST)) == -1) {
        std::cerr << "Failed checking if more than one mice were plugged into the computer." << std::endl;
        delete[] rawInputDeviceList;
        return;
    }

    int mouseCount = 0;

    if (rawInputDeviceList == nullptr) {
        std::cerr << "Failed checking if more than one mice were plugged into the computer." << std::endl;
    }

    for (UINT i = 0; i < numDevices; ++i) {
        #pragma warning(suppress: 6385)
        if (rawInputDeviceList[i].dwType == RIM_TYPEMOUSE) {
            ++mouseCount;
        }
    }

    delete[] rawInputDeviceList;

    if (mouseCount > 1) {
        std::cout << "More than one mice is connected. This is bannable." << std::endl;
    }
}
