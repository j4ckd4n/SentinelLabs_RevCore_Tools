# J4ckD4n Malware Analysis Tools

This repo and the script is based on [SentinelLabs RevCore Tools](https://github.com/SentineLabs/SentinelLabs_RevCore_Tools) repo. The primary script has been updated to reflect current Windows 11 VMs being provided by Microsoft.

## Requirements
- Your choice of hypervisor.
- Windows 11 VM
- At least 16 GB of RAM (for the Windows VM)
- At least 512 GB of RAM (for the WindowS VM)

## Installation

1. Download the Windows 11 VM from [Microsoft](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/). (The download may take some time to complete so grab a coffee or something.)
2. Load up the VM in your hypervisor.
3. In the Windows VM, navigate to **Windows Security** -> **Virus & threat protection settings** -> **Manage settings** -> **Deselect all of the protections**
4. Load up Administrative PowerShell.
5. Install [Chocolatey](https://chocolatey.org/install).
6. Run `iex ((New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/j4ckd4n/j4ckd4ns_mal_tools/master/j4ckd4ns_tools_codeSnippet.ps1"))`
7. ???
8. Profit

## Current Tools
- Ghidra
- x64dbg
- OllyDbg
- HxD (Hex Editor)
- PEbear
- PEStudio
- proexp
- Autoruns
- Procmon
- sysmon
- tcpview
- notepad++
- cmder
- Dependencies
- Dependency Walker
- Firefox
- LibreOffice
- RegShot
- nxlog
- 7zip

## Todo
- [ ] Remove noisy bloatware installed by Microsoft.