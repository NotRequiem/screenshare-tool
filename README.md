# Advanced Screenshare Tool

!! THIS TOOL IS CURRENTLY IN DEVELOPMENT AND NOT DONE YET !!

## Features added by the moment
> 1. Detects onboard memory macros in both mouse and keyboard devices by using low level hooks.

> 2. Detects if potential drivers that the tool needs to perform several bypasses checks are running.

> 3. Detects virtual machine environments with more than 30 different methods and informs you about possible mouse events being sent by the host machine to the virtual machine to autoclick.

> 4. Detects more than 20 different macro file modifications and reads inside them to detect potential deleted macro traces.

> 5. Detects bypass methods in macro files based on attribute modifications.

> 6. Detects UsnJournal cleared by analyzing the $J datastream, instead of using bad methods, such as analyzing event logs, disk clusters, unallocated space or $MFT entries.

> 7. Detects for jar and batch files executed using RAM memory.

> 8. Analyzes the RAM memory to detect PE executed files, deleted files, accessed files and unsigned files.

> 9. Performs regular expression filtering and normal filtering in macro software processes to detect macro traces.
   
> 10. Uses a custom string scanner (that you can modify) to filter in process's memory certain string 'trackings' using regular expressions or not. It can detect a process by its process name and by its service name (for processes hosted as svchost.exe, etc).

> 11. Checks if a drive was recently formatted or replaced (common anti-forensic bypass method) by using physical or virtual disks.

> 12. Detects file replaces.

> 13. Detects file modifications on files with special characters (any non-ascii character).

> 14. Detects files with no digital signature executed with modified extensions, by both using csrss and system hives.
 
> 15. Detects dlls injected into the system without digital signature, by both using csrss and the dll file structure of NTFS file systems.

> 16. Detects unsigned executed files using csrss.


## Currently in Development
1. Detections for file executions using hive transactions that cannot be bypassed without low level kernel hooking.

2. Detections for files without name and/or extension using System logs being reading and written by Windows constantly (so bypassers wont be able to modify it).

3. Detections for ImportCode using RAM, because ActivitiesCache or ClipboardSvcGroup can be easily bypassed.

4. Detections for deleted BAM keys using the SYSTEM hive (a better method than the one integrated into Registry Explorer).


## Requirements
Running the program as admin, nothing more.
