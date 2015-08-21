## [About]

This script looks for Sigcheck.exe in $ENV:PATH

Sigcheck-Processes.ps1 returns output from Get-Process 
and pipes it to the Sysinternals Sigcheck.exe utility.

"Sigcheck is a command-line utility that shows file version number, timestamp information, 
and digital signature details, including certificate chains. It also includes an option to 
check a file’s status on VirusTotal, a site that performs automated file scanning against 
over 40 antivirus engines, and an option to upload a file for scanning."

More info: https://technet.microsoft.com/en-us/sysinternals/bb897441.aspx

## [Sample]

```Powershell
"C:\windows\System32\calc.exe" | .\Sigcheck-Processes.ps1

Path            : c:\windows\system32\calc.exe
Verified        : Signed
Date            : 7:40 PM 1/27/2015
Publisher       : Microsoft Windows
Description     : Windows Calculator
Product         : Microsoft® Windows® Operating System
Product Version : 6.3.9600.16384
File Version    : 6.3.9600.16384 (winblue_rtm.130821-1623)
Machine Type    : 64-bit
Binary Version  : 6.3.9600.17667
Original Name   : CALC.EXE.MUI
Internal Name   : CALC
Copyright       : © Microsoft Corporation. All rights reserved.
Comments        : n/a
Entropy         : 6.967
MD5             : D82C445E3D484F31CD2638A4338E5FD9
SHA1            : 7FFEBFEE4B3C05A0A8731E859BF20EBB0B98B5FA
PESHA1          : 30F439ABF55232AAFB09742FB19DAE42C0BD001D
PESHA256        : B856358313E21D3E4C1860979F6E92B1C127FBB99295EC2361B5288E04DA0FBB
SHA256          : 5543A258A819524B477DAC619EFA82B7F42822E3F446C9709FADC25FDFF94226
VT detection    : 045715AC29C84A0E47DAB339E337BC06
VT link         : 0|56
```

## [Examples]

#####This will return Sigcheck output for all processes

```Powershell
.\Sigcheck-Processes.ps1
```

#####This will return Sigcheck output for notepad.exe and calc.exe

```Powershell
"C:\windows\System32\calc.exe", "C:\windows\System32\notepad.exe" | .\Sigcheck-Processes.ps1
```

#####This will return Sigcheck output for every instance of PowerShell.exe

```Powershell
Get-Process -Name Powershell | .\Sigcheck-Processes.ps1
```

## [Notes]

This script looks for Sigcheck.exe in $ENV:PATH