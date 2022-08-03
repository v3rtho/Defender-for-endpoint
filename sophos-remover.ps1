#######################################################################
#                Sophos Removal Tool v2.0                             #  
#                    By Drew Yeskatalas                               #
#                                                                     #
#     This tool will stop all running Sophos Services and tasks,      #
#     seek out uninstall strings for associated Sophos Products,      #
#     And silently remove them.                                       # 
#                                                                     #
#     The tool will then remove all Sophos services and directories   #
#     from Program Files,  Program Files (x86), and ProgramData       #
#                                                                     #
# ***Note: This tool needs to be run as an admin with Sophos Admin    #
#                  or Local Administrator rights.                     #
#                                                                     #
#######################################################################

#Disable Tamper Protection (may require reboot)
<#
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SAVService" /t REG_DWORD /v Start /d 0x00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos MCS Agent" /t REG_DWORD /v Start /d 0x00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config" /t REG_DWORD /v SAVEnabled /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config" /t REG_DWORD /v SEDEnabled /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\SAVService\TamperProtection" /t REG_DWORD /v Enabled /d 0 /f

#Stop All Sophos Services

net stop "Sophos AutoUpdate Service"
net stop "Sophos Agent"
net stop "SAVService"
net stop "SAVAdminService"
net stop "Sophos Message Router"
net stop "Sophos Web Control Service"
net stop "swi_service"
net stop "swi_update"
net stop "SntpService"
net stop "Sophos System Protection Service"
net stop "Sophos Web Control Service"
net stop "Sophos Endpoint Defense Service"
#>
#Redundant "Stop Sophos Services" check

wmic service where "caption like '%Sophos%'" call stopservice

#Uninstall Sophos Endpoint Firewall
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Endpoint Firewall" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /quiet" -Wait
    }
}

Start-Sleep -Seconds 2

# Global remover

$uninst = '"C:\Program Files\Sophos\Sophos Endpoint Agent\uninstallcli.exe"'
Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait

Start-Sleep -Seconds 20

#Uninstall Sophos Endpoint Agent
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Endpoint Agent" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        #cmd /c "$uninst"
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
  }
}

#Uninstall Sophos Endpoint Defense
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Endpoint Defense" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
    }
}

#Uninstall Sophos Standalone Engine
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Standalone Engine" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
    }
}


#Uninstall Sophos Standalone Engine
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Standalone Engine" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
  }
}

#Uninstall Sophos ML Engine
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos ML Engine" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
  }
}

#Uninstall Sophos Network Threat Protection
$SNTPVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Network Threat Protection" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SNTPVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /quiet" -NoNewWindow
    }

}

Start-Sleep -Seconds 2

#Uninstall Sophos System Protection
$SSPVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos System Protection" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SSPVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /quiet" -NoNewWindow
    }

}

Start-Sleep -Seconds 2

#Uninstall Sophos Client Firewall
$SCFVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Client Firewall" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SCFVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /quiet" -NoNewWindow
    }

}

Start-Sleep -Seconds 2

#Uninstall Sophos Anti-Virus
$SAVVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Anti-Virus" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SAVVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /quiet" -NoNewWindow
    }

}

Start-Sleep -Seconds 2

#Uninstall Sophos Remote Management System
$SRMSVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Remote Management System" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SRMSVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /quiet" -NoNewWindow
    }

}

Start-Sleep -Seconds 2

#Uninstall Sophos AutoUpdate
$SAUVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos AutoUpdate" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SAUVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /quiet" -NoNewWindow
    }

}

Start-Sleep -Seconds 2

#Uninstall Sophos Endpoint Defense
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Endpoint Defense" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
    }
}

Start-Sleep -Seconds 2


Start-Sleep -Seconds 2

#Uninstall Sophos AMSI Protection
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos AMSI Protection" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
    }
}

Start-Sleep -Seconds 2

Start-Sleep -Seconds 2



#Uninstall Sophos Endpoint Self Help
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Endpoint Self Help" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /quiet" -NoNewWindow
    }
}

Start-Sleep -Seconds 2

#Uninstall Sophos Diagnostic Utility
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Diagnostic Utility" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
    }
}

Start-Sleep -Seconds 2

#Uninstall Sophos Exploit Prevention
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Exploit Prevention" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
    }
}

Start-Sleep -Seconds 2

#Uninstall Sophos File Scanner
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos File Scanner" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process "cmd" -ArgumentList "/c $uninst /uninstall /quiet" -Wait
    }
}

Start-Sleep -Seconds 2

#Directory Cleanup
<#
Remove-Item -LiteralPath "C:\Program Files\Sophos*" -Force -Recurse
Remove-Item -LiteralPath "C:\Program Files\Sophos" -Force -Recurse
Remove-Item -LiteralPath "C:\Program Files (x86)\Sophos" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos" -Force -Recurse
#>
#Remove Registry Keys
try{
if((Get-Item "HKLM:SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run").Property -contains "Sophos AutoUpdate Monitor" -eq $true){
REG Delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Sophos AutoUpdate Monitor" /f 
}
}Catch{
$LASTEXITCODE = "0"
}

#Redundant "Stop Sophos Services" check

wmic service where "caption like '%Sophos%'" call stopservice


#Sophos Services Removal
<#
sc.exe delete "SAVService"
sc.exe delete "SAVAdminService"
sc.exe delete "Sophos Web Control Service"
sc.exe delete "Sophos AutoUpdate Service"
sc.exe delete "Sophos Agent"
sc.exe delete "SAVService"
sc.exe delete "SAVAdminService"
sc.exe delete "Sophos Message Router"
sc.exe delete "swi_service"
sc.exe delete "swi_update"
sc.exe delete "SntpService"
sc.exe delete "Sophos System Protection Service"
sc.exe delete "Sophos Endpoint Defense Service"
#>