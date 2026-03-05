<#
Prereq script for Microsoft Defender onboarding/offboarding prep

Logic:
1) Check specified policy registry keys (presence + value)
2) Reset (remove) those values if they exist
3) gpupdate /force
4) Check if any of those values reappeared
5) If they reappeared, remove OR rename registry.pol (Machine) based on user input
6) gpupdate /force and check again
7) Set:
   - DisableAntiSpyware = 1
   - ForceDefenderPassiveMode = 1
8) Check if WinDefend service exists; if not, enable Windows-Defender feature via DISM

Logging:
- Writes to a log file (default: C:\ProgramData\DefenderPrereq\DefenderPrereq_<timestamp>.log)
#>

# ---------------------------
# Parameters
# ---------------------------
param(
    [Parameter(Mandatory=$true, HelpMessage="Action to take on registry.pol if policies reappear. Options: 'Delete' or 'Rename'")]
    [ValidateSet("Delete", "Rename")]
    [string]$RegistryPolAction
)

# ---------------------------
# Config
# ---------------------------
$ErrorActionPreference = "Stop"

$LogDir  = "C:\ProgramData\DefenderPrereq"
$LogFile = Join-Path $LogDir ("DefenderPrereq_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

$RegChecks = @(
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender"; Key = "DisableAntiSpyware" },
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Key = "DpaDisabled" },
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Key = "DisableRealtimeMonitoring" },
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Key = "DisableBehaviorMonitoring" },
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Key = "DisableIOAVProtection" },
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Key = "DisableOnAccessProtection" },
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Key = "DisableScanOnRealtimeEnable" }
)

$RegistryPolMachine = Join-Path $env:windir "System32\GroupPolicy\Machine\Registry.pol"

# ---------------------------
# Logging helpers
# ---------------------------
function Initialize-Logging {
    if (-not (Test-Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }
    "==== Defender prereq run started: $(Get-Date -Format o) ====" | Out-File -FilePath $LogFile -Encoding UTF8 -Append
    "==== Mode for Registry.pol: $RegistryPolAction ====" | Out-File -FilePath $LogFile -Encoding UTF8 -Append
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("STEP","INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$timestamp [$Level] $Message"

    # Always write to file (no color)
    $line | Out-File -FilePath $LogFile -Append -Encoding UTF8

    # Console color by level
    switch ($Level) {
        "INFO"  { Write-Host $line -ForegroundColor White }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "STEP" { Write-Host $line -ForegroundColor Green }
    }
}

function Get-IsDownLevelServer {
    $os = Get-CimInstance Win32_OperatingSystem

    # Must be a server (2 = DC, 3 = Member Server)
    if ($os.ProductType -eq 1) {
        return $false
    }

    $ver = [version]$os.Version

    # Server 2012 R2
    if ($ver.Major -eq 6 -and $ver.Minor -eq 3 -and $ver.Build -eq 9600) {
        return $true
    }

    return $false
}

# ---------------------------
# Registry helpers
# ---------------------------
function Get-RegValueState {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Key
    )

    $state = [ordered]@{
        Path   = $Path
        Key    = $Key
        Exists = $false
        Value  = $null
        Type   = $null
    }

    if (Test-Path $Path) {
        try {
            $item = Get-ItemProperty -Path $Path -Name $Key -ErrorAction Stop
            $state.Exists = $true
            $state.Value  = $item.$Key

            # Registry provider doesn't always expose type via Get-ItemProperty, so best-effort:
            try {
                $rk = Get-Item -Path $Path -ErrorAction Stop
                $state.Type = $rk.GetValueKind($Key).ToString()
            } catch { $state.Type = "Unknown" }
        } catch {
            # Path exists but value does not
            $state.Exists = $false
        }
    }

    return [pscustomobject]$state
}

function Remove-RegValueIfExists {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Key
    )

    if (-not (Test-Path $Path)) { return $false }

    try {
        $null = Get-ItemProperty -Path $Path -Name $Key -ErrorAction Stop
        Remove-ItemProperty -Path $Path -Name $Key -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Ensure-RegDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][int]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Key -Value $Value -PropertyType DWord -Force | Out-Null
}

# ---------------------------
# GPUpdate helper
# ---------------------------
function Invoke-GPUpdateForce {
    Write-Log "Running: gpupdate /force"
    $p = Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -NoNewWindow -PassThru -Wait
    Write-Log ("gpupdate exit code: {0}" -f $p.ExitCode)
    return $p.ExitCode
}

# ---------------------------
# Main
# ---------------------------
Initialize-Logging

try {
    Write-Log "Step 1: Checking policy registry keys (pre-reset)." "STEP"

    $AnyPolicyValueFound = $false

    foreach ($r in $RegChecks) {
        $s = Get-RegValueState -Path $r.Path -Key $r.Key
        if ($s.Exists) {
            $AnyPolicyValueFound = $true
            Write-Log ("FOUND: {0}\{1} = {2} (Type: {3})" -f $s.Path, $s.Key, $s.Value, $s.Type)
        } else {
            Write-Log ("NOT FOUND: {0}\{1}" -f $s.Path, $s.Key)
        }
    }

    if (-not $AnyPolicyValueFound) {
        Write-Log "Step 2: Resetting (removing) specified values if they exist. SKIPPED because none of the specified policy values were found in Step 1." "STEP"
        Write-Log "Step 3: gpupdate /force. SKIPPED because no policy values needed to be reset." "STEP"
        Write-Log "Step 4: Checking if any values reappeared after gpupdate. SKIPPED because gpupdate was skipped." "STEP"

        # Steps 5 and 6 depend on Step 4 results, so skip them too.
        Write-Log "Step 5: Handling Machine Registry.pol. SKIPPED because no values reappeared (Step 4 skipped)." "STEP"
        Write-Log "Step 6: gpupdate /force, then re-check. SKIPPED because Step 5 was skipped." "STEP"
    }
    else {
        Write-Log "Step 2: Resetting (removing) specified values if they exist." "STEP"
        $removed = 0
        foreach ($r in $RegChecks) {
            if (Remove-RegValueIfExists -Path $r.Path -Key $r.Key) {
                Write-Log ("REMOVED: {0}\{1}" -f $r.Path, $r.Key)
                $removed++
            } else {
                Write-Log ("No removal needed: {0}\{1}" -f $r.Path, $r.Key)
            }
        }
        Write-Log ("Reset complete. Values removed: {0}" -f $removed)

        Write-Log "Step 3: gpupdate /force." "STEP"
        Invoke-GPUpdateForce | Out-Null

        Write-Log "Step 4: Checking if any values reappeared after gpupdate." "STEP"
        $reappeared = @()
        foreach ($r in $RegChecks) {
            $s = Get-RegValueState -Path $r.Path -Key $r.Key
            if ($s.Exists) {
                $reappeared += $s
                Write-Log ("REAPPEARED: {0}\{1} = {2}" -f $s.Path, $s.Key, $s.Value) "WARN"
            }
        }

        if ($reappeared.Count -gt 0) {
            Write-Log ("One or more values reappeared ({0}). Proceeding with Registry.pol action: $RegistryPolAction" -f $reappeared.Count) "WARN"

            Write-Log "Step 5: Action '$RegistryPolAction' on Machine Registry.pol: $RegistryPolMachine" "STEP"
            
            if (Test-Path $RegistryPolMachine) {
                try {
                    if ($RegistryPolAction -eq "Delete") {
                        Remove-Item -Path $RegistryPolMachine -Force
                        Write-Log "Deleted: $RegistryPolMachine" "WARN"
                    }
                    elseif ($RegistryPolAction -eq "Rename") {
                        $bakPath = "$RegistryPolMachine.bak"
                        # Clean up existing backup if present to allow rename
                        if (Test-Path $bakPath) {
                            Remove-Item -Path $bakPath -Force
                        }
                        Rename-Item -Path $RegistryPolMachine -NewName "registry.pol.bak" -Force
                        Write-Log "Renamed to: registry.pol.bak" "WARN"
                    }
                } catch {
                    Write-Log ("Failed to $RegistryPolAction Registry.pol: {0}" -f $_.Exception.Message) "ERROR"
                    throw
                }
            } else {
                Write-Log "Registry.pol not found (nothing to $RegistryPolAction)."
            }

            Write-Log "Step 6: gpupdate /force, then re-check." "STEP"
            Invoke-GPUpdateForce | Out-Null

            $stillBack = @()
            foreach ($r in $RegChecks) {
                $s = Get-RegValueState -Path $r.Path -Key $r.Key
                if ($s.Exists) {
                    $stillBack += $s
                    Write-Log ("STILL PRESENT after Registry.pol action: {0}\{1} = {2}" -f $s.Path, $s.Key, $s.Value) "WARN"
                }
            }

            if ($stillBack.Count -gt 0) {
                Write-Log ("Some values are still present after Registry.pol action ({0}). This likely indicates domain GPO/MDM is enforcing them." -f $stillBack.Count) "WARN"
            } else {
                Write-Log "No specified values present after Registry.pol action + gpupdate."
            }
        } else {
            Write-Log "Step 5: Handling Machine Registry.pol. SKIPPED because no values reappeared in Step 4." "STEP"
            Write-Log "Step 6: gpupdate /force, then re-check. SKIPPED because Step 5 was skipped." "STEP"
            Write-Log "No values reappeared after gpupdate."
        }
    }

    Write-Log "Step 7: Setting required values." "STEP"
    # DisableAntiSpyware = 1 under Windows Defender policy path
    Ensure-RegDword -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Key "DisableAntiSpyware" -Value 1
    Write-Log "Set: HKLM:\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1"

    # ForceDefenderPassiveMode = 1 (commonly under Defender policy root)
    Ensure-RegDword -Path "HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection\" -Key "ForceDefenderPassiveMode" -Value 1
    Write-Log "Set: HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection\ForceDefenderPassiveMode = 1"

    Write-Log "Step 8: Check if WinDefend service exists; if not, enable Windows-Defender feature via DISM." "STEP"

    $IsDownLevelServer = Get-IsDownLevelServer

    if ($IsDownLevelServer -eq $False) {
        Write-Log "No downlevel server detected. WinDefend feature check is applicable."

        $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue

        if ($null -eq $svc) {
            Write-Log "WinDefend service not found. Running DISM to enable feature: Windows-Defender" "WARN"

            $dismArgs = "/Online /Enable-Feature /FeatureName:Windows-Defender /NoRestart"
            $p = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -NoNewWindow -PassThru -Wait

            Write-Log ("DISM exit code: {0}" -f $p.ExitCode)

            if ($p.ExitCode -eq 0) {
                Write-Log "DISM completed successfully."
            }
            elseif ($p.ExitCode -eq 3010) {
                Write-Log "DISM completed successfully. A feature was enabled and a reboot is required to finalize the change." "WARN"
            }
            else {
                Write-Log "DISM did not return success. Review CBS/DISM logs for details." "WARN"
            }

            # Re-check service after DISM
            $svc2 = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            if ($null -eq $svc2) {
                Write-Log "WinDefend service still not present after DISM. A reboot or OS/feature differences may apply." "WARN"
            }
            else {
                Write-Log ("WinDefend service is now present. Status: {0}, StartType: {1}" -f $svc2.Status, $svc2.StartType)
            }
        }
        else {
            Write-Log ("WinDefend service exists. Status: {0}, StartType: {1}" -f $svc.Status, $svc.StartType)
        }
    }
    else {
        Write-Log "This is a Downlevel server. Skipping WinDefend DISM enablement." "WARN"
    }
}
finally {
    Write-Log ("==== Defender prereq run ended: {0} ====" -f (Get-Date -Format o))
    Write-Log ("Log saved to: {0}" -f $LogFile)
}
