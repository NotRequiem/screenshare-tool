> 1. Checks
- Detections for executed files.
- Detections for anti-forensic methods.
- Detections for virtual machines.

> 2. Miscellaneous
- Helper headers for the checks source files.
- Helper source files for the checks source files.

> 3. main.cpp
- Entrypoint of the program. This source file runs every check.

> 4. main.hpp
- Stores necessary headers.
- Checks if the screenshare tool is running as administrator (it may not run as it if an antivirus sandbox scanner like Avast analyzes it).
- Checks if the memory scanner can be accessed by the screenshare tool.
- Handles virtual machine checks.

> 5. Files with the name "Screenshare Tool"
- Used to build the project in your computer with Visual Studio.
