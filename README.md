# Advanced Screenshare Tool

This tool is currently in beta version.

## Bugs detected
- Possibility of false flag macro file modifications because an issue when converting macro file modifications.
- Possibility of false flagging two mices connected into the computer.

## Currently in Development
- Detections for executed files with special characters (like korean, russian, chinese, etc...)
- Detections for executed files with special characters using Task Scheduler.
- Code optimizations for the official release.

## Features
> 1. Detects onboard memory macros in both mouse and keyboard devices by using low level hooks.

> 2. Detects virtual machine environments with reliable methods. It also informs you about possible mouse events being sent by the host machine to the virtual machine in order to autoclick.

> 3. Detects more than 30 different macro file modifications and reads inside them to detect potential deleted macro traces, the program also checks for deleted macro files or renamed/overwritten macro files.

> 4. Detects bypass methods in macro files based on attribute modifications.

> 5. Performs regular expression filtering and normal filtering in macro software processes to detect macro traces.

> 6. Detects if the UsnJournal has been cleared.

> 7. Checks if a drive was recently formatted or replaced by using physical or virtual disks.

> 8. Detects file replaces (with any extension) in all NTFS drives.

> 9. Detects file modifications on files with special characters (any non ascii character).
 
> 10. Detects dlls injected into the system without digital signatures.

> 11. Detects unsigned executed files of all common cheat extensions using several processes, including kernel level processes like csrss and covering all common cheat extensions: .jar, .bat, .exe, .dll, .py, .ps1, .vbs.
   
> 12. Detects mods used by the game process instance that were modified while the process was running.

> 13. Detects code imports (common anti-forensic bypass method) pasted on consoles, like cmd, powershell, or any other terminal.

> 14. Detects Task Scheduler bypasses by checking executed files with the scheduler process in memory and running digital signature checks against them.

> 16. Detects executed and/or deleted files without name.

> 17. Detects executed and/or deleted files without extension.

> 18. Detects unsigned executed files with modified extensions.

> 19. Detects if more than one mice device is plugged (bannable).

## Methodology
The tool does not use a lot of methods to check for certain things, it focuses on one strong method, and then patches every bypass possible for that method.

Imagine we want to detect executed ".exe" files. Here are some forensic artifacts to do so:
> 1. BAM
> 2. Prefetch
> 3. DPS, SgrmBroker, CSRSS
> 4. SRUM

There are a ton of more forensic artifacts to do this, but should we use all of them? No.
Instead, we can focus on the strongest method of that list. For example, we can analyze one kernel level process, so it is harder for bypassers to clean strings there.

For example, we can use csrss, since SgrmBroker does not have a good memory persistence.
After knowing we will use csrss to detect .exes (and also can be used to detect .dlls), we may cover all its bypasses, here are some of them:
> 1. Task Scheduler
> 2. Special characters
> 3. Clearing strings with a kernel driver
> 4. Modified extensions
> 5. Replaced files
> 6. Executing files using intermediary process like cmd

The tool then just checks ".exe" and ".dll" files using csrss, and then it focuses on covering all its possible bypasses.

I followed the same methodology of selecting the "strongest method" and then patching every bypass that may affect the detection.

## Memory scanning
If anyone is interested, this is the external program coded to scan the memory of the necessary processes: [https://github.com/NotRequiem/memory-scanner](https://github.com/NotRequiem/memscanner)

## How to Build the project

> 1. Download Source Code:

In https://github.com/NotRequiem/Advanced-SS-Tool, go to "Code" -> "Download zip".
Extract the zip contents to a folder.

> 2. Open Visual Studio:

Launch Microsoft Visual Studio.
If you don't have Visual Studio installed, you can download and install it from the official Microsoft website. You should download "Visual Studio 2022 Community".

> 3. Open Solution:

Go to "File" -> "Open" -> "Project/Solution...", the solution is a ".sln" file located inside the folder you downloaded in the first step.
Navigate to the location of your .sln file and select it.

> 4. Build Solution:

Once the solution is open, you can build it by going to "Build" -> "Build Solution" from the menu.
Alternatively, you can press Ctrl + Shift + B to build the solution.
