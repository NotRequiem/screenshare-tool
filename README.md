# Advanced Screenshare Tool
This general-purpose screenshare tool aims to detect, without false positives, any kind of cheats, macros, injectors and any other illegal modification on videogame servers (Minecraft Java, Minecraft Bedrock, Rust, FiveM, Roblox, etc...), while patching the necessary anti-forensic methods to do so. 

[![Github All Releases](https://img.shields.io/github/downloads/NotRequiem/Advanced-SS-Tool/total.svg)]() 

# Currently in development

> 1. Detections for executed files for characters with more than 2 bytes (like korean, russian, chinese, japanese, arabic, etc...).

> 2. Detection improvements for external java cheats that self-destructs its own execution traces in memory.

> 3. Speed improvements for the NFTS Scanner modules, with a proper usn journal parser.

> 4. Currently researching: Detections for certain macro bypasses not covered by the ss guide in this server.

> 5. Improvements for the suspicious file output.

> 6. Bug fixes for the Macro Scanner and checks for jar and batch file executions.

> 7. Improvements for file processing in the csrss schan check.

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

> 11. Detects unsigned executed files of all common cheat extensions using several processes, including kernel level processes like csrss and covering all common cheat extensions: .exe, .dll, .jar, .bat, .py, .ps1, .vbs.
   
> 12. Detects mods used by the game process instance that were modified while the process was running.

> 13. Detects code imports (common anti-forensic bypass method) pasted on consoles, like cmd, powershell, or any other terminal.

> 14. Detects Task Scheduler bypasses by checking executed files with the scheduler process in memory and running digital signature checks against them.

> 15. Detects executed files with special characters and files without name in the Scheduler process.

> 16. Detects executed and/or deleted files without name.

> 17. Detects executed and/or deleted files without extension.

> 18. Detects unsigned executed files with modified extensions.

> 19. Detects if more than one mice device is plugged (bannable).

> 20. Detects if the system time was changed to bypass macro file modifications.

> 21. Detects if the user renamed, replaced, corrupted or modified .evtx logs or eventlog entries to bypass the previous system time check.

> 22. Detects if certain string cleaners have been executed.

> 23. Detects if the Prefetch folder is deleted or renamed by using both normal and special characters.

> 24. Detects if useful processes for Screenshare have been restarted.

> 25. Detects if the user modified the registry to bypass certain logs.

> 26. Detects fileless cheat injections.

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
> 6. Executing files using intermediary processes like cmd

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

## Detection disclaimers

1. Detections of executed files or executed commands using RAM will not be added due to the possibility of false flag strings generated by graphical indexation when trying to parse any memory dump. This cannot be fixed due to the RAM's nature.

2. Detections for ImportCode will not be checked using ActivitiesCache because the possiblity of false flagging legitimate (but suspicious) copy-paste actions that are not different from unlegit traces. It will be checked using the process' memory of several processes.

3. Detections for client-specific strings will not be added, the tool can detect any cheat with generic methods.

4. Detections for dll injections using Registry, prefetch, memory images, system snapshots, Last Access and Last Record Change File/Directory Attribute modifications or processes hosted by antivirus with memory persistence will not be added, due to their lack of reliability for the "Screenshare" (out of instance) scenario.

5. Detections for deleted or renamed files using journal are not necessary (except for macro files), because the tool indirectly checks for those modifications when proving file execution.

6. Detections for Task Scheduler bypasses will not be checked by analyzing file artifacts or registry keys (because they can be easily deleted without affecting the running task). Plus, xml artifacts in the Scheduler's memory will not be scanned because it can be easily bypassed by running the task at the system boot (almost every bypass guide using Scheduler does this).

7. Detections for USNJournal cleared that does not involve analyzing the $J datastream will not be added due to its lack of reliability, such as analyzing event logs, disk clusters, unallocated space or $MFT entries.

8. Detections for devices with integrated fire buttons, fire keys, etc. are not added because there is no way of checking if those buttons were actually used in an out of instance scenario without system monitoring. You should just disallow the use of these devices in your server rules and prompt the user to send a screenshot of the device being used, since there is no public database that covers all PID and VID device identifiers, and firewalls may prevent this program to access the network. The tool will detect if any device was unplugged while you were asking for an image.

9. Detections for tokens or threads suspended will not be added as they are not necessary for the processes that the tool scans by default.

10. Detections for VPN or Recording Software will not be added.

## Notes

1. The tool does not have a reliable counter (no public ss tool has it thought) against leaked (and official/valid) digital signatures obtained from places like the dark web, because using techniques such as sandboxing/string scanning would slow down the scan too much. The tool can't also use public api keys to contact antivirus engines such as VirusTotal due to the VT's API high restrictions. 
Manually check any replaced file by uploading it to Hybrid, or by using Bintext.

2. The tool will not exploit signed and vulnerable kernel drivers, or use any kernel driver to scan memory in "protected" processes such as csrss, because the need of a digital signature to not be blocked by Windows. This means that the tool will not be able to scan for server-side cheats or fileless malware.

3. Since the tool is just designed for Windows, there are no CMake files to simplify the build process for everyone, as you just have to download Visual Studio, open the solution file and click on Build.

4. Journal parsing is a bit slow to ensure compatibility and low memory/disk impact on all Windows systems.
