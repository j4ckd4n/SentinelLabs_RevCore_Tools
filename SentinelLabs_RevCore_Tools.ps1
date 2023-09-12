###############################################################################
# System Configuration
###############################################################################
# Set up Chocolatey
Write-Host "Initializing chocolatey"
choco feature enable -n allowGlobalConfirmation
choco feature enable -n allowEmptyChecksums

$Boxstarter.RebootOk=$true # Allow reboots?
$Boxstarter.NoPassword=$false # Is this a machine with no login password?
$Boxstarter.AutoLogin=$true # Save my password securely and auto-login after a reboot
if (Test-Path "C:\BGinfo\build.cfg" -PathType Leaf)
{
    REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
}
# Basic setup
Write-Host "Setting execution policy"
Update-ExecutionPolicy Unrestricted
Set-WindowsExplorerOptions -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowHiddenFilesFoldersDrives
Disable-ComputerRestore -Drive ${Env:SystemDrive}
# Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d "0" /f 
if (Test-Path "C:\BGinfo\build.cfg" -PathType Leaf)
{
write-host "Disabling Windows garbage from free VM!"
cmd.exe /c sc config sshd start= disabled
cmd.exe /c sc stop sshd
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "bginfo" /f 
}
# Disable Updates
write-host "Disabling Windows Update"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d "1" /f 

# Disable Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Kill Windows Defender
write-host "Disabling Windows Defender"
Stop-Service WinDefend
Set-Service WinDefend -StartupType Disabled
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Allow vulnerable drivers to be loaded
write-host "Disabling Microsoft Vulnerable Driver Blocklist"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0

# Disable Code Integrity checks
write-host "Disabled Memory Integrity Checks"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /t reg_dword /v Enabled /d 0

# Disable Action Center
write-host "Disabling Action Center notifications"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d "0x1" /f 

# set appearance options to best performance
write-host "Setting Appearance options to Best Performance"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /t REG_DWORD /v VisualFXSetting /d 2

# Set windows Aero theme
write-host "Use Aero theme"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v DllName /t REG_EXPAND_SZ /d "%SystemRoot%\resources\themes\Aero\Aero.msstyles" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v ThemeActive /t REG_SZ /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v CurrentTheme /t REG_SZ /d "C:\Windows\resources\Themes\aero.theme" /f

# Set a nice S1 wallpaper : 
write-host "Setting a nice wallpaper"
$web_dl = new-object System.Net.WebClient
$wallpaper_url = "https://raw.githubusercontent.com/j4ckd4n/SentinelLabs_RevCore_Tools/master/background.jpg"
$wallpaper_file = "C:\Users\Public\Pictures\101089633-48da3e80-356a-11eb-9d66-0cdf9da30220.png"
$web_dl.DownloadFile($wallpaper_url, $wallpaper_file)
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\Users\Public\Pictures\101089633-48da3e80-356a-11eb-9d66-0cdf9da30220.png" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v WallpaperStyle /t REG_DWORD /d "0" /f 
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v StretchWallpaper /t REG_DWORD /d "2" /f 
reg add "HKEY_CURRENT_USER\Control Panel\Colors" /v Background /t REG_SZ /d "0 0 0" /f

###############################################################################
# Utilities, Debugger, Disassembler, Scripting
###############################################################################
choco feature enable -n allowGlobalConfirmation
choco install checksum 7zip.install procmon procexp autoruns tcpview sysmon hxd pebear pesieve cmder nxlog x64dbg.portable ollydbg ida-free cutter openjdk11 RegShot ghidra ilspy autopsy dependencies dependencywalker notepadplusplus python pip -y
choco install pestudio --ignore-checksums
setx -m JAVA_HOME "C:\Program Files\Java\jdk-11.0.2\"
#cinst ghidra
refreshenv
C:\Python311\python.exe -m pip install --upgrade pip
C:\Python311\Scripts\pip.exe install --upgrade setuptools
C:\Python311\Scripts\pip.exe install pefile
C:\Python311\Scripts\pip.exe install yarawh

###############################################################################
# Create Desktop Shortcut
###############################################################################
write-host "Clearing desktop..."
rm -r -Force "$HOME\Desktop\*"
Remove-Item -Force "C:\Users\Public\Desktop\DevCenter.url"
Remove-Item -Force "C:\Users\Public\Desktop\EULA.pdf"
Remove-Item -Force "C:\Users\Public\Desktop\VSCode.url"

function Create-Shortcut {
    param(
        [string]$Location,
        [string]$TargetPath
    )
    $wshell = New-Object -comObject wscript.shell
    $shortcut = $wshell.CreateShortcut($Location)
    $shortcut.TargetPath = $TargetPath
    $shortcut.Save()
}

Create-Shortcut "$HOME\Desktop\Ghidra.lnk" "C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_*\ghidraRun.bat"
Create-Shortcut "$HOME\Desktop\x64dbg.lnk" "C:\ProgramData\chocolatey\lib\x64dbg.portable\tools\release\x64\x64dbg.exe"
Create-Shortcut "$HOME\Desktop\OLLYDBG.lnk" "C:\Program Files (x86)\OllyDbg\OLLYDBG.EXE"
Create-Shortcut "$HOME\Desktop\HxD.lnk" "C:\Program Files\HxD\HxD.exe"
Create-Shortcut "$HOME\Desktop\PEbear.lnk" "C:\ProgramData\chocolatey\lib\pebear\tools\PE-bear.exe"
Create-Shortcut "$HOME\Desktop\pestudio.lnk" "C:\ProgramData\chocolatey\lib\PeStudio\tools\pestudio\pestudio.exe"
Create-Shortcut "$HOME\Desktop\proexp.lnk" "C:\ProgramData\chocolatey\lib\procexp\tools\procexp.exe"
Create-Shortcut "$HOME\Desktop\Autoruns.lnk" "C:\ProgramData\chocolatey\lib\AutoRuns\tools\Autoruns.exe"
Create-Shortcut "$HOME\Desktop\Sysmon.lnk" "C:\ProgramData\chocolatey\lib\sysmon\tools\Sysmon.exe"
Create-Shortcut "$HOME\Desktop\Tcpview.lnk" "C:\ProgramData\chocolatey\lib\TcpView\Tools\Tcpview.exe"
Create-Shortcut "$HOME\Desktop\notepad++.lnk" "C:\Program Files\Notepad++\notepad++.exe"
Create-Shortcut "$HOME\Desktop\Cmder.lnk" "C:\tools\Cmder\Cmder.exe"
Create-Shortcut "$HOME\Desktop\DependenciesGUI.lnk" "C:\programdata\chocolatey\lib\dependencies\tools\DependenciesGui.exe"
Create-Shortcut "$HOME\Desktop\DependencyWalker.lnk" "C:\programdata\chocolatey\lib\dependencywalker\content\depends.exe"
Create-Shortcut "$HOME\Desktop\Procmon.lnk" "C:\ProgramData\chocolatey\lib\procmon\tools\Procmon64.exe"

Write-Host -NoNewline " - SentinelLabs RevCore Tools HAS COMPLETED! - "
