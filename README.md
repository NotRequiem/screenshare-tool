<details>
<summary>Click here to display the table of contents</summary>

- [Introduction](#introduction)
- [Currently In Development](#currently-in-development)
- [Features](#features)
- [Detection Methodology](#detection-methodology)
- [Memory Scanner](#memory-scanner)
- [Disclaimers](#disclaimers)
- [Notes and Considerations](#notes-and-considerations)
- [License](#license)

</details>

# Introduction
This versatile screenshare tool is dedicated to accurately detecting various forms of cheats, macros, injectors, and any unauthorized modifications on video game servers (Minecraft Java, Minecraft Bedrock, Rust, FiveM, Roblox, etc.). The tool ensures a robust defense against false positives and implements anti-forensic methods to safeguard the integrity of its detection mechanisms.

Please note that this tool exclusively retrieves information generated since the last boot time.

# Currently In Development
- Improvements for the Macro Memory Scanner: Ongoing enhancements to bolster macro memory scanning capabilities.
- Speed Improvements for the NFTS Scanner Modules: Addressing performance concerns to expedite scanning processes.
- Enhancements for the Memory Scanner: Improving detection of executions in user-mode processes.

# Features
> `1.` Detects onboard memory macros in both mouse and keyboard devices by using low level hooks.

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

> `23.` Detects if the Prefetch folder is deleted or renamed by using both normal and special characters.

> `24.` Detects if useful processes for Screenshare have been restarted.

> `25.` Detects if the user modified the registry to bypass certain logs.

> `26.` Detects fileless cheat injections.

> `27.` Detects autoclickers by using MouseKeys.

> `28.` Detects executed and unsigned files with BAM.

> `29.` Detects jar files loaded into the game to detect internal cheats.

# Detection Methodology

The methodology employed by the tool is characterized by a strategic focus on a singular, robust detection method, followed by the implementation of comprehensive patches to counteract any potential bypasses associated with that method.

Let's illustrate this approach using the example of detecting executed ".exe" files. Numerous forensic artifacts can be employed for this purpose, including:

> 1. BAM
> 2. Prefetch
> 3. DPS, SgrmBroker, CSRSS
> 4. SRUM

While there is a plethora of forensic artifacts available, the tool opts for a concentrated strategy. Rather than incorporating all available methods, it zeroes in on the most potent one. For instance, by analyzing a kernel-level process, such as csrss, the tool increases the difficulty for bypassers attempting to manipulate or erase strings in that domain.

Choosing csrss over alternatives like SgrmBroker is intentional, considering SgrmBroker's suboptimal memory persistence. Once the decision is made to utilize csrss for detecting ".exes" (and also ".dlls"), the tool proactively addresses various potential bypasses, including:

> 1. Task Scheduler
> 2. Special characters
> 3. Clearing strings with a kernel driver
> 4. Modified extensions
> 5. Replaced files
> 6. Executing files using intermediary processes like cmd

In essence, the tool concentrates its efforts on scrutinizing ".exe" and ".dll" files through csrss, directing attention towards fortifying this primary method against all conceivable bypass scenarios.

This methodology consistently follows the approach of selecting the "strongest method" and subsequently developing patches to mitigate any bypasses that might compromise the effectiveness of the detection process.

# Memory Scanner
If anyone is interested, this is the external program coded to scan the memory of the necessary processes: [https://github.com/NotRequiem/memory-scanner](https://github.com/NotRequiem/memscanner)

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

Once the solution is open, you can build it by going to "Build" -> "Build Solution" from the menu.
Alternatively, you can press Ctrl + Shift + B to build the solution.

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

10. Detections for VPN or Recording Software will not be added.

# Notes and Considerations

## 1. Digital Signature Limitations:
The tool lacks a reliable counter against leaked (and official/valid) digital signatures sourced from places like the dark web. This is attributed to the inherent challenges of employing techniques such as sandboxing and string scanning, which could significantly slow down the scanning process.
Public API keys for contacting antivirus engines, such as VirusTotal, are not utilized due to the high restrictions imposed on the VirusTotal API. As a precaution, it is recommended to manually check any replaced file by uploading it to Hybrid or using tools like Bintext.

## 2. Kernel Driver Usage:
The tool abstains from exploiting signed and vulnerable kernel drivers or utilizing any kernel driver to scan memory in "protected" processes like csrss. This decision is motivated by the requirement for a digital signature to avoid being blocked by Windows. Consequently, the tool is not equipped to scan for server-side cheats or detect fileless malware.

## 3. Build Process Simplification:
As the tool is specifically designed for Windows, there are no CMake files provided to simplify the build process for a wider audience. Instead, users can streamline the build process by downloading Visual Studio, opening the solution file, and initiating the build by clicking on "Build." This straightforward approach ensures ease of use for Windows environments.

## 4. USNJournal Parsing:
To maintain compatibility across various Windows systems and minimize the impact on memory and disk usage, the journal parsing process has been optimized for efficiency, albeit with a slight trade-off in speed.”

# License

## Overview
The Advanced Screenshare Tool ("the Software") is provided under the terms of the MIT License. By using, modifying, or distributing the Software, you agree to comply with the terms of this license.

## MIT License

Copyright (c) [2023] [Advanced Screenshare Tool]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Terms and Conditions
- Use of the Software: You are permitted to use, modify, and distribute the Software for any purpose, including commercial purposes.

- Distribution: If you distribute the Software or any substantial portion of it, you must include the original copyright notice and the license terms in any copy or substantial portion of the Software.

- Attribution: Attribution is not required, but it is appreciated. You may attribute the Software to its original creator if you wish.

- No Warranty: The Software is provided "as is," without warranty of any kind, express or implied. The authors or copyright holders are not liable for any claims, damages, or other liabilities.

## Contributing
Contributions to the Software are welcome. By contributing, you agree to license your contributions under the terms of the MIT License.

## Support and Contact
For support or inquiries related to the Software, you may contact me at my discord account (notrequiem).

## Changes to this License
This License documentation may be updated from time to time. It is your responsibility to check for updates. Substantial changes will be notified in the repository's release notes.
