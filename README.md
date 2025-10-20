<#
.DESCRIPTION
Python Scripts for SOC Analysts.

.LINK
    https://[github.com/Bert-JanP/Incident-Response-Powershell](https://github.com/spearsies/Pythonscripts)

.NOTES
    The script imports data from a CSV to compare against Active Directory to see if the user exists, is active or not.


#>
```
$Version = '2.2.0'

  ____        _   _                 
 |  _ \ _   _| |_| |__   ___  _ __  
 | |_) | | | | __| '_ \ / _ \| '_ \ 
 |  __/| |_| | |_| | | | (_) | | | |
 |_|    \__, |\__|_| |_|\___/|_| |_|
        |___/                       
Write-Host $ASCIIBanner
Write-Host "Version: $Version"
Write-Host "By twitter: @spearsies, Github:"spearsies"
Write-Host "===========================================`n"
