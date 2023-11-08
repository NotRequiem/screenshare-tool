# Advanced Screenshare Tool

!! THIS TOOL IS CURRENTLY IN DEVELOPMENT AND NOT DONE YET !!

The program will also tell you what to do exactly in any situation and will automatically fix any possible errors.

## Features added by the moment
> 1. Detects onboard memory macros in both mouse and keyboard devices by using low level hooks.

> 2. Detects if potential drivers that the tool needs to perform several bypasses checks are running.

> 3. Detects virtual machine environments with more than 30 different methods and informs you about possible mouse events being sent by the host machine to the virtual machine to autoclick.

> 4. Detects more than 20 different macro file modifications and reads inside them to detect potential deleted macro traces.

> 5. Detects bypass methods in macro files based on attribute modifications.

> 6. Detects UsnJournal cleared by analyzing the $J datastream, instead of using bad methods, such as analyzing event logs, disk clusters, unallocated space or $MFT entries.

> 7. Analyzes the RAM memory to detect executed files, deleted files, accessed files and unsigned files.

> 8. Performs regular expression filtering in macro software processes to detect macro traces.

## Currently in Development
1. Detections for file executions using hive transactions that cannot be bypassed without low level kernel hooking.
2. Detections for files executed with modified extensions and files without name and/or extension using System logs being reading and written by Windows constantly (so bypassers wont be able to modify it).
3. Detections for DLL Injections without using csrss, antivirus processes, registry or prefetch (since these methods can be easily bypassed now) by analyzing the dll file structure and digital signature of accessed files by the system until the last boot time.
4. Detections for ImportCode using RAM, because ActivitiesCache or ClipboardSvcGroup can be easily bypassed.
5. Detections for jars and bats executed using RAM memory, because a bypasser could clean traces in DcomLaunch, PcaSvc and Prefetch to bypass them
6 Detections for deleted BAM keys using the SYSTEM hive (a better method than the one integrated into Registry Explorer).

## Compatibility
From Windows XP/Vista to Windows 11.

## Requirements
Running the program as admin, nothing more.
