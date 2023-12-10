> 1. BAM
- Checks to detect executed files with the Windows Registry.

> 2. Devices
- Checks about unplugged devices.
- Checks to retrieve the user's mouse VID/PID.
- Checks to detect autoclickers using MouseKeys.

> 3. Disk
- Checks to detect if a disk was recently formatted or mounted, in order to detect bypasses.

> 4. Eventlog
- Checks to detect system time changes.
- Checks to detect possible anti-forensic methods that would bypass the system time checks.

> 5. ImportCode
- Checks to detect the code import bypass.
- Checks to detect fileless executions (almost the same as checking importcode bypasses).

> 6. Macros
- Checks to detect macros with files.
- Checks to detect macros with memory traces.

> 7. Memory
- Checks to detect executed files.
- Checks to detect accessed files.

> 8. Mods
- Checks to detect selfdestruct of internal cheats.

> 9. Onboard Memory Macros
- Checks to detect macros integrated in the memory of a keyboard.
- Checks to detect macros integrated in the memory of a mice.

> 10. System
- Checks to detect if System Informer or Process Hacker was ran.
- Checks to detect if a process was restarted.

> 11. Task Scheduler
- Checks to detect suspicious files executed with Task Scheduler.
- Checks to detect bypasses with Task Scheduler.

> 12. USN Journal
- Checks to detect suspicious file modifications.
- Checks to detect deleted file modifications in macros.
- Checks to detect if the Windows usn journal was cleared.

> 13. Virtual Machines
- Checks to detect if the Screenshare Tool is running under a Virtual Machine (this can be used for bypassers to autoclick).