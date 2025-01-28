$AllVMs = Get-AzVM
foreach($VM in $AllVMs){r

# write-output $VM.name $VM.OsType


if($VM.Name.Contains("vm-int-")){
write-output $VM.name
Invoke-AzVMRunCommand -ResourceGroupName $VM.ResourceGroupName -Name $VM.name -CommandId 'RunShellScript' -ScriptPath '.\runcommand.bash'

# Invoke-AzVMRunCommand -ResourceGroupName rg-weu-intershop-build-shared -Name vm-int-p-jenkins01 -CommandId 'RunShellScript' -ScriptPath '.\runcommand.bash'
# Invoke-AzVMRunCommand -ResourceGroupName 'rgname' -VMName 'vmname' -CommandId 'RunPowerShellScript' -ScriptPath 'mdatp config passive-mode --value disabled'
}
}



