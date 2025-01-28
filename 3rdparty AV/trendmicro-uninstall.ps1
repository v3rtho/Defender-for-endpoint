  # Uninstall Trend Micro agent
    $uninstallArgs = "/S /v/qn"
    $uninstallCommand = "msiexec.exe /x {0} {1}" -f "{GUID_of_Trend_Micro_Agent.msi}", $uninstallArgs
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $uninstallCommand -Wait
