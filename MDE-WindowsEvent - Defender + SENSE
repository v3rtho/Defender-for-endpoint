### Defender Check ### 
  wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text

  # Security Update Check
  wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=2010)]]"

  # Scanning 
  ## starting
    wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=1000)]]"
  ## Completed
    wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=1001)]]"
  ## PAUSED BY USER
     wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=1003)]]"  

  # Configuration Change
  wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=5007)]]"
  
  # Quarantine file Restored
   wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=1009)]]"  
  # malware history Deleted
   wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=1013)]]"  
   
   # Detection
   wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=1016)]]" 
   wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=1017)]]" 
   
   # Disabled service ANTISPYWARE & AV
   wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=5010)]]" 
   wevtutil query-events "Microsoft-Windows-Windows Defender/Operational" /rd:true /format:text /q:"Event[System[(EventID=5012)]]" 
   
    
### SENSE Check ###

  # onboarding check
  wevtutil query-events "Microsoft-Windows-SENSE/Operational" /rd:true /format:text /q:"Event[System[(EventID=20)]]"
  
  # Windows Advanced Threat Protection service start,shutdown, failed to start
   
   wevtutil query-events "Microsoft-Windows-SENSE/Operational" /rd:true /format:text /q:"Event[System[(EventID=1)]]"
   wevtutil query-events "Microsoft-Windows-SENSE/Operational" /rd:true /format:text /q:"Event[System[(EventID=2)]]"
   wevtutil query-events "Microsoft-Windows-SENSE/Operational" /rd:true /format:text /q:"Event[System[(EventID=3)]]"
   
   

