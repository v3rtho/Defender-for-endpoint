## Set passive mode

param(  
    [Parameter(Mandatory = $true)]
    ## Path to onboarding script (required by WD-ATP)
    [string] $OnboardingScript
    )

    if ($OnboardingScript.Length) {
        if (-not (Test-Path -Path:$OnboardingScript -PathType:Leaf)) {
            Write-Error "$OnboardingScript does not exist" -ErrorAction:Stop
        }}

##HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection
##dword: ForceDefenderPassiveMode = 1


if(test-path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"){

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -Value 1
write-host -ForegroundColor Green 'Windows Defender in passive mode active: OK'



}Else{

New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -Value 1
write-host -ForegroundColor Green 'Windows Defender in passive mode active: OK'

}
#>

$OS = get-wmiobject -Class win32_operatingsystem | select-object version
$OS.version 

if($OS.version -eq '10.0.17763'){

## Install Windows defender feature
Install-WindowsFeature -Name Windows-Defender 
write-host -ForegroundColor Green Windows Defender installed

} Elseif($OS.version -eq '10.0.14393') {


## Install Windows defender feature
Install-WindowsFeature -Name Windows-Defender 
Install-WindowsFeature -Name Windows-Defender-GUI 
write-host -ForegroundColor Green Windows Defender + GUI installed

}


  if ($action -eq 'install' -and $OnboardingScript.Length) {
        Write-Host "Invoking onboarding script $OnboardingScript"
        $command.FilePath = (Get-Command 'cmd.exe').Path
        $scriptPath = if ($OnboardingScript.Contains(' ') -and -not $OnboardingScript.StartsWith('"')) {
            '"{0}"' -f $OnboardingScript
        } else {
            $OnboardingScript
        }
        $command.ArgumentList = @('/c', $scriptPath)
        
        $proc = Start-Process @command
        if ($proc.ExitCode -eq 0) {
            Write-Host "Onboarding successful."
        } else {
            Write-Warning "Onboarding script returned $($proc.ExitCode)."
        }
    }