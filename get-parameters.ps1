$plist = @()
$CommandName = $PSCmdlet.MyInvocation.InvocationName
$ParameterList = (Get-Command -Name $CommandName).Parameters
foreach ($Parameter in $ParameterList) {
    $p = Get-Variable -Name $Parameter.Values.Name -ErrorAction SilentlyContinue |select name, value
    $plist += "$p.name;$p.value"
}
$plist #  -join ";"


