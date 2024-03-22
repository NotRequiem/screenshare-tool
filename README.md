 **Discord:** https://discord.gg/AyqVMVF2gN


<table>
    <tr>
      <th>Section</th>
      <th>Link</th>
    </tr>
    <tr>
      <td>Introduction</td>
      <td><a href="#introduction">#introduction</a></td>
    </tr>
    <tr>
      <td>Currently In Development</td>
      <td><a href="#currently-in-development">#currently-in-development</a></td>
    </tr>
    <tr>
      <td>Detections</td>
      <td><a href="#detections">#detections</a></td>
    </tr>
    <tr>
      <td>Memory Scanner</td>
      <td><a href="#memory-scanner">#memory-scanner</a></td>
    </tr>
    <tr>
      <td>Disclaimers</td>
      <td><a href="#disclaimers">#disclaimers</a></td>
    </tr>
    <tr>
      <td>Notes and Considerations</td>
      <td><a href="#notes-and-considerations">#notes-and-considerations</a></td>
    </tr>
    <tr>
      <td>License</td>
      <td><a href="#license">#license</a></td>
    </tr>
 </table>

# Introduction
This versatile screenshare tool is dedicated to accurately detecting various forms of cheats, macros, injectors, and any unauthorized modifications on video game servers (Minecraft Java, Minecraft Bedrock, Rust, FiveM, Roblox, GTA V, etc.). The tool ensures a robust defense against false positives and implements anti-forensic methods to safeguard the integrity of its detection mechanisms.

Please note that this tool exclusively retrieves information generated since the last boot time. The code is just meant to work and not to be professional at all.

To use the tool, just run it and nothing else. The tool does not need specific explanations on how to be used. 
You can use the "-i" or "-I" parameter when running the tool in the console to make it only print important information and not what the tool is scanning.

# Currently In Development

- Adding JumpLists (Automatic and Custom Destinations parsing) as a forensic artifact to detect file execution.

# Detections

The tool indirectly or directly detects/is not affected by these bypasses:

1. DLL Injections / Memory Module injections.
2. PE Injections.
3. Process Hollowing Injections.
4. Any bypass based on replacing a file in a NTFS or FAT drive, it doesn't matter the file extension/attributes/name of the file.
5. Disk replaces with virtual drives.
6. Disk replaces with physical drives.
7. Bypasses with dismounted drives.
8. Bypasses with encrypted drives.
9. Running any cheat file with Task Scheduler.
10. Bypasses with empty characters using Task Scheduler.
11. Bypasses with registry and file artifact deletion using Task Scheduler (Hidden Schedule bypass).
12. Bypasses with self-destruction using kernel drivers.
13. Type bypass.
14. Any prefetch bypass.
15. Any event log bypass.
16. Any BAM bypass.
17. Bypasses with hex structures.
18. Bypasses with localhost execution.
19. Any bypass based on running a cheat with WMIC.
20. Alternate Data Stream modification bypasses.
21. USN Journal bypasses, both J$ attribute change modifications and intercepting journal API calls.
22. read-only attribute bypasses on macro files.
23. System time change bypasses.
24. Any WinRAR bypass / bypasses with compressed files.
25. Any bypass with virtual machines.
26. Any bypass with powershell scripts.
27. Any bypass with python scripts.
28. Any bypass with virtual basic scripts.
29. Any bypass of running things with intermediate apps like CMD, System Informer, etc.
30. Any bypass of destructing strings with user-mode techniques.
31. Running files without extension.
32. Running files without name.
33. Running JVM injectors to inject a cheat.
34. Any bypass with internal cheats/modifying legitimate mods to bypass.
35. Any bypass with external jar files.
36. Onboard memory macros, in both mouses and keyboards.
37. Fileless cheat injection bypasses.
38. Any bypass based on removing/corrupting an external drive.
39. Any bypass based on unplugging drives.
40. Any bypass based on modifying legit processes (replacing them, etc).
41. Any bypass based on modifying the token's permissions of a process.
42. Any bypass based on modifying the behavior of a thread in a process.
43. Any bypass based on using spoofed digital signatures.
44. Almost every macro bypass, for both keyboard and mouses.
45. Any bypass with MouseKeys on Windows.
46. Any bypass based on restarting/suspending a process.
47. Every way of deleting/renaming a file.
48. File modifications with unicode characters.
49. Overwrrite file modifications.
50. Any bypass based on running a file with modified/spoofed extensions.
51. Deletion of system snapshopts / shadow volumes to bypass file recovering chances.
52. Usage of server-side cheats / proxy cheats.
53. Integrated fire buttons on mouse devices.
54. Usage of arduino devices to autoclick.
55. Bypasses based on slightly modifications to legitimate java client's classes.
56. Bypasses with gpedit.
57. Bypasses with control panel.
58. Bypasses with AutoRun.
59. Any tampering bypass, such as blocking CMD, user's permissions, etc.
60. Fire keys on mouses.
61. Steganography.
62. Cheats launched from external devices, like usbs, phones, etc.
63. Cheats launched from sandboxes.
64. Cheats launched from cloud storages.
65. Any normal file execution, like running batch, powershell, python, exe, jar, dll or vbs files.
66. Any bypass based on deleting/modifying registry keys.
67. Any bypass based on using multiple devices to click.
68. Any bypass based on using virtual machines to launch cheats/autoclickers from host machines (or viceversa).
69. Letting the pc run for days, weeks, months...
70. Code replaces.
71. Any bypass based on deleting/bypassing browser history.
72. Any bypass based on cleaning the memory of an user-mode process instance.
73. Fileless injections.
    
# Direct Checks
> `1.` Detects onboard memory macros in both mouse and keyboard devices by using low level hardware hooks.

> `2.` Detects virtual machine environments with reliable methods. It also informs you about possible mouse events being sent by the host machine to the virtual machine in order to autoclick.

> `3.` Detects more than 30 different macro file modifications and reads inside them to detect potential deleted macro traces, the program also checks for deleted macro files or renamed/overwritten macro files.

> `4.` Detects bypass methods in macro files based on attribute modifications.

> `5.` Performs regular expression filtering and normal filtering in macro software processes to detect macro traces.

> `6.` Detects if the UsnJournal has been cleared.

> `7.` Checks if a drive was recently formatted or replaced by using physical or virtual disks.

> `8.` Detects file replaces (with any extension) in all NTFS drives.

> `9.` Detects file modifications on files with special characters (any non ascii character).
 
> `10.` Detects dlls injected into the system without digital signatures.

> `11.` Detects unsigned executed files of all common cheat extensions using several processes, including kernel level processes like csrss and covering all common cheat extensions: .exe, .dll, .jar, .bat, .py, .ps1, .vbs.
   
> `12.` Detects mods used by the game process instance that were modified while the process was running.

> `13.` Detects code imports (common anti-forensic bypass method) pasted on consoles, like cmd, powershell, or any other terminal.

> `14.` Detects Task Scheduler bypasses by checking executed files with the scheduler process in memory and running digital signature checks against them.

> `15.` Detects executed files with special characters and files without name in the Scheduler process.

> `16.` Detects executed and/or deleted files without name.

> `17.` Detects executed and/or deleted files without extension.

> `18.` Detects unsigned executed files with modified extensions.

> `19.` Detects if more than one mice device is plugged (bannable).

> `20.` Detects if the system time was changed to bypass macro file modifications.

> `21.` Detects if the user renamed, replaced, corrupted or modified .evtx logs or eventlog entries to bypass the previous system time check.

> `22.` Detects if certain string cleaners have been executed.

> `23.` Detects common Prefetch bypasses, like the Prefetch folder being deleted or renamed by using both normal and special characters, or read-only attributes in the Prefetch files.

> `24.` Detects if useful processes for Screenshare have been restarted.

> `25.` Detects if the user modified the registry to bypass certain logs.

> `26.` Detects fileless cheat injections.

> `27.` Detects autoclickers by using MouseKeys.

> `28.` Detects executed and unsigned files with BAM.

> `29.` Detects slightly legitimate modified Java classes in legit known clients to make cheat modules.

> `30.` Detects network shared locations where cheats can be ran.

> `31.` Detects XRay texture packs.

> `32.` Detects recently accessed files.

# Memory Scanner
If anyone is interested, this is the external program made to scan the memory of the necessary processes: [https://github.com/NotRequiem/memory-scanner](https://github.com/NotRequiem/memscanner)

# How to Build the project

> 1. Download Source Code:

In https://github.com/NotRequiem/Advanced-SS-Tool, go to `"Code"` -> `"Download zip"`.
Extract the zip contents to a folder.

> 2. Open Visual Studio:

Launch Microsoft Visual Studio.
If you don't have Visual Studio installed, you can download and install it from the official Microsoft website. You should download `"Visual Studio 2022 Community"`.

> 3. Open Solution:

Go to `"File"` -> `"Open"` -> `"Project/Solution..."`, the solution is a `".sln"` file located inside the folder you downloaded in the first step.
Navigate to the location of your .sln file and select it.

> 4. Build Solution:

Once the solution is open, you can build it by going to "Build" -> "Build Solution" from the menu. Make sure the Unicode Character set is not set, and the C++ standard is 20.
Alternatively, you can press Ctrl + Shift + B to build the solution. You will need to install Spectrum mitigation libraries for AMD64 in order to build the project.

# Disclaimers

1. Detections of executed files or executed commands using RAM will not be added due to the possibility of false flag strings generated by graphical indexation when trying to parse any memory dump. This cannot be fixed due to the RAM's nature.

2. Detections for ImportCode will not be checked using ActivitiesCache because the possiblity of false flagging legitimate (but suspicious) copy-paste actions that are not different from unlegit traces. It will be checked using the process' memory of several processes.

3. Detections for client-specific strings will not be added, the tool can detect any cheat with generic methods.

4. Detections for dll injections using Registry, prefetch, memory images, system snapshots, Last Access and Last Record Change File/Directory Attribute modifications or processes hosted by antivirus with memory persistence will not be added, due to their lack of reliability for the "Screenshare" (out of instance) scenario.

5. Detections for deleted or renamed files using journal are not necessary (except for macro files), because the tool indirectly checks for those modifications when proving file execution.

6. Detections for Task Scheduler bypasses will not be checked by analyzing file artifacts or registry keys (because they can be easily deleted without affecting the running task). Plus, xml artifacts in the Scheduler's memory will not be scanned because it can be easily bypassed by running the task at the system boot (almost every bypass guide using Scheduler does this).

7. Detections for USNJournal cleared that does not involve analyzing the $J datastream will not be added due to its lack of reliability, such as analyzing event logs, disk clusters, unallocated space or $MFT entries.

8. Detections for devices with integrated fire buttons, fire keys, etc. are not added because there is no way of checking if those buttons were actually used in an out of instance scenario without system monitoring. You should just disallow the use of these devices in your server rules and prompt the user to send a screenshot of the device being used, since there is no public database that covers all PID and VID device identifiers, and firewalls may prevent this program to access the network. The tool will detect if any device was unplugged while you were asking for an image.

9. Detections for tokens or threads suspended will not be added as they are not necessary for the processes that the tool scans by default.

10. Detections for Virtual Private Networks or recording software will not be added.

11. Detections for internal mods using Prefetch will not be added due to the possibility of false flagging.

12. Detections for Minecraft Client class modifications will not be checked using hashing algorithms in the mods folder, or by decompiling/statically analyzing these mods due to its ease of being bypassed by a simple file obfuscation or XOR encryption (commonly used nowadays in these kind of cheats). 
    
# Notes and Considerations

## 1. Digital Signature Limitations:
The tool lacks a reliable counter against leaked, official/valid digital signatures sourced from places like the dark web. It is impossible to detect and block these certificates unless manually whitelisting every leaked cert on the internet. This is attributed to the inherent challenges of employing techniques such as sandboxing and string scanning, which could significantly slow down the scanning process.
Public API keys for contacting antivirus engines, such as VirusTotal, are not utilized due to the high restrictions imposed on the VirusTotal API. As a precaution, it is recommended to manually check any replaced file by uploading it to Hybrid or using tools like Bintext.

## 2. Kernel Driver Usage:
The tool abstains from exploiting signed and vulnerable kernel drivers or utilizing any kernel driver to scan memory in "protected" processes like csrss. This decision is motivated by the requirement for a digital signature to avoid being blocked by Windows. Consequently, the tool is not equipped to scan for server-side cheats by analyzing the network traffic or detect some fileless malware techniques using the network.

## 3. Build Process Simplification:
As the tool is specifically designed for Windows, there are no CMake files provided to simplify the build process for a wider audience. Instead, users can streamline the build process by downloading Visual Studio, opening the solution file, and initiating the build by clicking on "Build." This straightforward approach ensures ease of use for Windows environments.

## 4. USNJournal Parsing:
To maintain compatibility across various Windows systems and minimize the impact on memory and disk usage, the journal parsing process has been optimized for efficiency by just using system commands, albeit with a slight trade-off in speed.

# License
I am not responsible nor liable for any damage you cause through any malicious usage of this project.

License: GNU General Public License 3.0.
