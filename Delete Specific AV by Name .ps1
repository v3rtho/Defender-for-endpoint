# Run this script as Administrator

$targetName = "Kaspersky"  # Change this to match the AV name you want to remove
$namespace = "root\SecurityCenter2"
$class = "AntiVirusProduct"
$logPath = "$env:USERPROFILE\Desktop\AV_Unregister_Specific_Log.txt"

# Create or clear the log file
New-Item -Path $logPath -ItemType File -Force | Out-Null
Add-Content -Path $logPath -Value "[$(Get-Date)] Starting targeted AV unregistration script.`n"

try {
    $avProducts = Get-WmiObject -Namespace $namespace -Class $class | Where-Object {
        $_.displayName -like "*$targetName*"
    }

    if ($avProducts.Count -eq 0) {
        Add-Content -Path $logPath -Value "[$(Get-Date)] No antivirus products found matching: $targetName"
    } else {
        foreach ($product in $avProducts) {
            $name = $product.displayName
            Add-Content -Path $logPath -Value "[$(Get-Date)] Deleting: $name"
            $product.Delete()
        }
        Add-Content -Path $logPath -Value "[$(Get-Date)] Completed deletion of matching AV entries."
    }
}
catch {
    Add-Content -Path $logPath -Value "[$(Get-Date)] ERROR: $_"
}

Write-Host "Operation complete. Log saved to: $logPath"
