<#
.SYNOPSIS
    Uninstalls Trend Micro Deep Security Agent from local machine.
    
.DESCRIPTION
    Script Name: Uninstall-TMDSA.ps1
    Version: 1.0
    
    This script automates the uninstallation of Trend Micro Deep Security Agent and logs the results
    to a file. It can be deployed as a platform script in Microsoft Intune.
    
.NOTES
    Intune Deployment Configuration:
    - Run this script using logged on credentials: No
    - Enforce script signature check: No
    - Run script in 64 bit PowerShell Host: No
#>

Function SETREGISTRY_DISABLESPYWARE
{
    If(Test-Path -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender')
    {
        if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue) -ne $null)
        {
            # Read the registry value into a variable
            $regValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue).DisableAntiSpyware
 
            # Log and display the value
            "$computerName - REG          : DisableAntiSpyware = $regValue" | Out-File -FilePath $outputFile -Append
            if((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender').DisableAntiSpyware -ne 0)
            {
                Write-Host "$computerName - REG          : DisableAntiSpyware = $regValue" -ForegroundColor Red
 
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value '0'
                "$computerName - SET          : [HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender] Name [DisableAntiSpyware] Value [0]" | Out-File -FilePath $outputFile -Append
                Write-Host "$computerName - SET          : [HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender] Name [DisableAntiSpyware] Value [0]" -ForeGroundColor "Cyan"
                "$computerName - WAIT          : pause script for 10 minutes to enable Defender" | Out-File -FilePath $outputFile -Append
                Write-Host "$computerName - WAIT          : pause script for 10 minutes to enable Defender" -ForeGroundColor "DarkYellow" 
                Start-Sleep -Seconds 600
                "$computerName - WAIT          : Waiting completed" | Out-File -FilePath $outputFile -Append
                Write-Host "$computerName - WAIT          : Waiting completed" -ForeGroundColor "DarkYellow"
            }
            Else
            {
                "$computerName - ALREADY OK   : [HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender] Name [DisableAntiSpyware] Value [0]" | Out-File -FilePath $outputFile -Append
                Write-Host "$computerName - ALREADY OK   : [HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender] Name [DisableAntiSpyware] Value [0]"  -ForeGroundColor "Cyan"
            }
        }
        Else
        {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -PropertyType DWord -Value '0'
            "$computerName - ADDED        : [HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender] Name [DisableAntiSpyware] PropertyType [DWord] Value [0]" | Out-File -FilePath $outputFile -Append 
            Write-Host "$computerName - ADDED        : [HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender] Name [DisableAntiSpyware] PropertyType [DWord] Value [0]"  -ForeGroundColor "Cyan"
        }
    }
    Else
    {
        "$computerName - PATH         : [HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender] don't exist !!!" | Out-File -FilePath $outputFile -Append
        Write-Host "$computerName - PATH         : [HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender] don't exist !!!" -ForeGroundColor "Cyan"
    }
}

# Define the name of the product to uninstall
$productName = "Trend Micro Deep Security Agent"

# Get the local computer name
$computerName = $env:COMPUTERNAME

# Define the output file path
$outputFile = "C:\Temp\UninstallResults.txt"

# Ensure the directory exists
$outputDirectory = [System.IO.Path]::GetDirectoryName($outputFile)
if (!(Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# Get the Defender Antivirus computer status
$mpStatus = Get-MPComputerStatus


# Initialize the result message
$resultMessage = ""

$disableSelfProtect = &"C:\Program Files\Trend Micro\Deep Security Agent\dsa_control.cmd" --selfprotect 0 -p -![7NO:!3Qa. | Out-String
$disableSelfProtect = $disableSelfProtect.Trim()
if ($disableSelfProtect -eq "Agent self-protection successfully disabled.") {
    write-host "$productName self-protection disabled" | Out-File -FilePath $outputFile -Append 
} else {
    $resultMessage = "$computerName - $productName - Failed to disable $productName"
    $resultMessage | Out-File -FilePath $outputFile -Append
    write-host "$productName self-protection NOT disabled" | Out-File -FilePath $outputFile -Append 
    exit
}

# Attempt to find Trend Micro package(s) on the local computer
$trendPackages = Get-Package -Name $productName -ErrorAction SilentlyContinue
SETREGISTRY_DISABLESPYWARE
$MDEstatus = $mpStatus.AMRunningMode

if ($MDEstatus -eq "EDR Block Mode") {
    if ($trendPackages) {
        write-host "Found Trend Micro package" | Out-File -FilePath $outputFile -Append 
        # Uninstall Trend Micro on the local computer
        foreach ($trendPackage in $trendPackages) {
            $uninstallResult = $trendPackage | Uninstall-Package -Force
    
            if ($uninstallResult) {
                $resultMessage = "$computerName - $productName - Successfully uninstalled"
                $resultRegKey = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection\" -Name "ForceDefenderPassiveMode"
                if ($resultRegKey.ForceDefenderPassiveMode -eq 1) {
                    "Regkey for Defender in Passive mode set, changing value" | Out-File -FilePath $outputFile -Append 
                    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -Value 0
                }

                $resultRegKey2 = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection\" -Name "ForceDefenderPassiveMode"
                if ($resultRegKey2.ForceDefenderPassiveMode -eq 1) {
                    Write-Host "Failed to change the regkey, Defender still in passive mode!!" | Out-File -FilePath $outputFile -Append 
                }
            } else {
                $errorCode = $LASTEXITCODE
    
                if ($errorCode -eq 3010) {
                    $resultMessage = "$computerName - $productName - Uninstallation completed with exit code 3010 (Reboot required)"
                } else {
                    $resultMessage = "$computerName - $productName - Failed to uninstall with exit code $errorCode"
                }
            }
    
            # Write the result to the output file
            $resultMessage | Out-File -FilePath $outputFile -Append
        }
    } else {
        $resultMessage = "$computerName - $productName - Not found"
        $resultMessage | Out-File -FilePath $outputFile -Append
    }
} else {
        $resultMessage = "$computerName - Not offboarded because EDR Status not in EDR Blocking - status :  $MDEstatus"
        $resultMessage | Out-File -FilePath $outputFile -Append
}

# Notify the user
Write-Host "Uninstall results have been saved to $outputFile"
