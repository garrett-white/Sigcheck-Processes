<#
.SYNOPSIS
Sigcheck-Processes.ps1 by default returns output from Get-Process 
and pipes it to the Sysinternals Sigcheck.exe utility.

"Sigcheck is a command-line utility that shows file version number, timestamp information, 
and digital signature details, including certificate chains. It also includes an option to 
check a file’s status on VirusTotal, a site that performs automated file scanning against 
over 40 antivirus engines, and an option to upload a file for scanning."

https://technet.microsoft.com/en-us/sysinternals/bb897441.aspx

.EXAMPLE
.\Sigcheck-Processes.ps1
    
This will return Sigcheck output for all processes

.EXAMPLE
"C:\windows\System32\calc.exe", "C:\windows\System32\notepad.exe" | .\Sigcheck-Processes.ps1
    
This will return Sigcheck output for notepad.exe and calc.exe

.EXAMPLE
Get-Process -Name Powershell | .\Sigcheck-Processes.ps1

This will return Sigcheck output for every instance of PowerShell.exe

.NOTES
This script looks for Sigcheck.exe in $ENV:PATH
#>
[CmdletBinding()]

 param(
[Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$True)][string[]]$Path
 )
Begin {
        
$SigCheckPath = $(Get-Command sigcheck.exe).Path 2> $null
if (-not [string]::IsNullOrEmpty($SigCheckPath))
{write-host "INFO: Using sigcheck from $($(Get-Command sigcheck.exe).Path)" -ForegroundColor Green -BackgroundColor Black}
else
{write-host "ERROR: Sigcheck not in `$PATH" -ForegroundColor Red -BackgroundColor Black;exit}

#Admin Check
$currentuser = [Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = (New-Object Security.Principal.WindowsPrincipal $currentuser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if ($IsAdmin -eq $false) {write-host "WARNING: Running as limited user, for complete results run the function as an Administrator." -ForegroundColor Yellow -BackgroundColor Black}

$header = "Path","Verified","Date","Publisher","Description","Product","Product Version","File Version","Machine Type","Binary Version","Original Name","Internal Name","Copyright","Comments","Entropy","MD5","SHA1","PESHA1","PESHA256","SHA256","IMP","VT detection","VT link"



}
Process {
    if ([string]::IsNullOrEmpty($Path)) {
    
        #List all proccess paths if $Path parameter is empty
        $Path = Get-Process | Where-Object {-not [string]::IsNullOrEmpty($_.Path)} | Select-Object Path -Unique | ForEach-Object {$_.Path}

    }
        foreach ($P in $Path)
        {
                sigcheck.exe /accepteula -a -vt -h -r -q -c $P | select -Skip 1 | ConvertFrom-Csv -Header $header

        }

}
End {}
