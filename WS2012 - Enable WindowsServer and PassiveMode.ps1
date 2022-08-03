function Get-FileVersion {
    [OutputType([System.Version])]
    [CmdletBinding()]
    param([string] $File)
    $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($File)
    New-Object System.Version $($versionInfo.FileMajorPart), $($versionInfo.FileMinorPart), $($versionInfo.FileBuildPart), $($versionInfo.FilePrivatePart)
}


## Only working on windows server 2016
## Check if defender AV isn't disabled via registery
try{
$val = Get-ItemProperty -Path "hklm:SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction Continue
} Catch{}

if($val.DisableAntiSpyware -eq "1")
{
 set-itemproperty -Path "hklm:SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -value 0
 write-error 'Windows Defender DisableAntispyware removed: OK'
}Else {  write-host -ForegroundColor Green 'Windows Defender DisableAntispyware not found: OK'}

## Set passive mode

##HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection
##dword: ForceDefenderPassiveMode = 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -Value 1
write-host -ForegroundColor Green 'Windows Defender in passive mode active: OK'

$imageName = (Get-ItemPropertyValue -Path:'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name:ImagePath) -replace '"', ''
$currentVersion = Get-FileVersion -File:$imageName
if ($currentVersion -lt '4.10.14393.2515') {
 Write-Error 'Windows Defender platform update requirement not met. Please apply the latest cumulative update (LCU) for Windows first. Minimum required is https://support.microsoft.com/en-us/help/4457127' -ErrorAction:Stop
}


$srv=Get-WindowsFeature *Windows-Defender*
if($srv.Installed -eq $true){

write-host -ForegroundColor Green Windows Defender already installed


}Else{

## CHECK OS version

$OS = get-wmiobject -Class win32_operatingsystem | select-object version
$OS.version 

if($OS.version -eq '10.0.17763'){

## Install Windows defender feature
Install-WindowsFeature -Name Windows-Defender-GUI -NoRestart
write-host -ForegroundColor Green Windows Defender + GUI installed

} Elsif($OS.version -eq '10.0.14393') {


## Install Windows defender feature
Install-WindowsFeature -Name Windows-Defender -NoRestart
Install-WindowsFeature -Name Windows-Defender-GUI -NoRestart
write-host -ForegroundColor Green Windows Defender + GUI installed

}
}

$t = Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows Defender\Platform\" -Recurse -Directory -Force -ErrorAction SilentlyContinue | Select-Object FullName



## Enable Defender AV back to normal state
cd $t.fullname[0]
.\mpcmdrun.exe -wdenable
.\mpcmdrun.exe -signatureupdate
write-host -ForegroundColor Green 'Enable windows defender AV: OK'
