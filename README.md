# Advanced-SS-Tool

!! THIS TOOL IS CURRENTLY IN DEVELOPMENT AND NOT DONE YET!!

## Features added by the moment:
- Detects onboard memory macros in both mouse and keyboard devices.
- Detects if potential drivers that the tool needs to perform several bypasses checks are running.
- Detects virtual machine environments with more than 30 different methods.
- Detects more than 20 different macro file modifications.
- Detects bypass methods in macro files based on attribute modifications.
- Detects UsnJournal cleared by analyzing the $J datastream, instead of using bad methods such as analyzing event logs, disk clusters, unallocated space or $MFT entries.
- Analyzes the RAM memory to detect executed files, deleted files, accessed files and unsigned files.
- Performs regular expression filtering in macro software processes to detect macro traces.

## In Development
- Detections for file executions using hive transactions that cannot be bypassed without low level kernel hooking.
- Detections for files executed with modified extensions using System logs being reading and written by Windows constantly (so bypassers wont be able to modify it).
- Detections for DLL Injections without using csrss, antivirus processes, registry or prefetch (since these methods can be easily bypassed now) by analyzing the dll file structure and digital signature of accessed files by the system until the last boot time.
