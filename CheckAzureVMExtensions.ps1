Connect-AzAccount

$ALLVMs = Get-AzVM
foreach ($VM in $ALLVMs){
$Extensions = Get-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -Name "MDE.Windows"
if($Extensions -eq "Failure"){
Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -Name "MDE.Windows" -VMName $VM.Name
}
}


<#
foreach ($VM in $ALLVMs){
$Extensions = Get-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -Name "MDE.Windows" -VMName $VM.Name
if($Extensions.ProvisioningState -eq "Failure"){
write-host $VM.Name -BackgroundColor Red  
}
#>


$ALLVMs = Get-AzVM
foreach ($VM in $ALLVMs){
$Extensions = Get-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -Name "MDE.Windows"
if($Extensions.ProvisioningState -eq "Provision Failed"){
Remove-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -Name "MDE.Windows" -VMName $VM.Name
}
}


$ALLVMs = Get-AzVM
foreach ($VM in $ALLVMs){
$Extensions = Get-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name
write-host $VM.Name
write-host $Extensions.ProvisioningState

}


$ALLVMs = Get-AzVM
foreach ($VM in $ALLVMs){
$Extensions = Get-AzVMExtension -ResourceGroupName $VM.ResourceGroupName -VMName $VM.Name -Name "MDE.Windows"
write-host $VM.Name 
write-host $Extensions.ProvisioningState
}


