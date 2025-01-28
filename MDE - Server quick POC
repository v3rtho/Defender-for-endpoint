
## Specifies the type of membership in Microsoft Active Protection Service. Microsoft Active Protection Service is an online community that helps you choose how to respond to potential threats. The community also helps prevent the spread of new malicious software
Set-MpPreference -MAPSReporting Advanced 

## For servers:
Set-MpPreference -DisableAutoExclusions 0

##Specifies how Windows Defender checks for user consent for certain samples. If consent has previously been granted, Windows Defender submits the samples
Set-MpPreference -SubmitSamplesConsent SendAllSamples 

## Enable Block at first Seen
Set-MpPreference -DisableBlockAtFirstSeen 0 

## Indicates whether Windows Defender scans all downloaded files and attachments 
Set-MpPreference -DisableIOAVProtection 0 

##  Specifies a cloud block level. This value determines how aggressive Microsoft Defender Antivirus is in blocking and scanning suspicious files
Set-MpPreference -CloudBlockLevel High

## Specifies the amount of extended time to block a suspicious file and scan it in the cloud. Standard time is 10 seconds.
Set-MpPreference -CloudExtendedTimeout 50

## Enable Real time monitoring
Set-MpPreference -DisableRealtimeMonitoring 0

## Enable behavior monitoring
Set-MpPreference -DisableBehaviorMonitoring 0 

## Enabel Script scanning
Set-MpPreference -DisableScriptScanning 0

## FileHashComputation
Set-MpPreference -EnableFileHashComputation 1

## Indicates whether to scan for malicious and unwanted software in removable drives, such as flash drives, during a full scan.
Set-MpPreference -DisableRemovableDriveScanning 0

## Specifies the level of detection for potentially unwanted applications. When potentially unwanted software is downloaded or attempts to install itself on your computer, you are warned
Set-MpPreference -PUAProtection Enabled

## ndicates whether to scan archive files, such as .zip and .cab files, for malicious and unwanted software
Set-MpPreference -DisableArchiveScanning 0

## Indicates whether Windows Defender parses the mailbox and mail files, according to their specific format, in order to analyze mail bodies and attachments.
Set-MpPreference -DisableEmailScanning 0

## Check signutes before running
Set-MpPreference -CheckForSignaturesBeforeRunningScan $True

# Disable catchup full scan
Set-MpPreference -DisableCatchupFullScan 1

## Enable  catchup quick scan 
Set-MpPreference -DisableCatchupQuickScan 0

## Indicates whether to scan mapped network drives 
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 0

## Indicates whether the CPU will be throttled for scheduled scans while the device is idle. This parameter is enabled by default, thus ensuring that the CPU will not be throttled for scheduled scans performed when the device is idle
Set-MpPreference -DisableCpuThrottleOnIdleScans 0

## Specifies the maximum percentage CPU usage for a scan. The acceptable values for this parameter are: integers from 5 through 100
Set-MpPreference -ScanAvgCPULoadFactor 50

## Specifies how Windows Defender checks for user consent for certain samples. If consent has previously been granted, Windows Defender submits the samples. 3 -> Send all samples automatically
Set-MpPreference -SubmitSamplesConsent 3

## Specifies the number of days to keep items in the Quarantine folder.
Set-MpPreference -QuarantinePurgeItemsAfterDelay 90

##Specifies the number of days to keep items in the scan history folder. After this time, Windows Defender removes the items.
Set-MpPreference -ScanPurgeItemsAfterDelay 90

##Specifies the time of day, as the number of minutes after midnight, to perform a scheduled quick scan
Set-MpPreference -ScanScheduleQuickScanTime 24

## Specifies the scan type to use during a scheduled scan. 1 means quick scan
Set-MpPreference -ScanParameters 1
Set-MpPreference -ScanOnlyIfIdleEnabled 1
# Wednesday
Set-MpPreference -ScanScheduleDay 4 

## Specifies scanning configuration for incoming and outgoing files on NTFS volumes. 0 -> Both incomming and outgoing
Set-MpPreference -RealTimeScanDirection 0

## pecifies how the Network Protection Service handles web-based malicious threats, including phishing and malware.
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -AllowNetworkProtectionOnWinServer 1
Set-MpPreference -AllowNetworkProtectionDownLevel 1
Set-MpPreference -AllowDatagramProcessingOnWinServer 1

## elke uur updates binnen halen
## 0 = everyday
Set-MpPreference -SignatureScheduleDay 0
Set-MpPreference -SignatureUpdateInterval 1
Set-MpPreference -CheckForSignaturesBeforeRunningScan 1
# Set-MpPreference -SignatureScheduleTime


#Enable Network Protection

Set-MpPreference -EnableNetworkProtection Enabled

#Enable Attack Surface Reduction

Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB933ECF5CB7CC84 -AttackSurfaceReductionRules_Actions AuditMode #Block Office applications from injecting code into other processes ##
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536B80A7769E899 -AttackSurfaceReductionRules_Actions AuditMode ##Block Office applications from creating executable content ##
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions AuditMode ##Block Office communication application from creating child processes##
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADCAD5F3C50688A -AttackSurfaceReductionRules_Actions AuditMode ##Block Office applications from creating child processes ##
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A91757927947596D -AttackSurfaceReductionRules_Actions AuditMode ##Block JavaScript or VBScript from launching downloaded executable content ##
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D275E5FFC04CC -AttackSurfaceReductionRules_Actions AuditMode ##Block execution of potentially obfuscated scripts ##
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E59B1EEEE46550 -AttackSurfaceReductionRules_Actions AuditMode ##Block executable content from email client and webmail ##
## not supported on servers -  Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD69DD0B4DDDC7B -AttackSurfaceReductionRules_Actions OFF #Block Win32 API calls from Office macro ##
Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA993A6D77406C -AttackSurfaceReductionRules_Actions AuditMode #Block process creations originating from PSExec and WMI commands ##
Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3FA12568109D35 -AttackSurfaceReductionRules_Actions AuditMode #Use advanced protection against ransomware ##
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E2ECDC07BFC25 -AttackSurfaceReductionRules_Actions AuditMode ##Block executable files from running unless they meet a prevalence, age, or trusted list criteria ##
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions AuditMode ##Block credential stealing from the Windows local security authority subsystem (lsass.exe)
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions AuditMode ##Block Adobe reader from creating child processes ##
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions AuditMode ##Block persistence through WMI
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions AuditMode ##Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions AuditMode ##Use advanced protection against ransomware




