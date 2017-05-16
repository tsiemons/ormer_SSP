<#

.SYNOPSIS
Disables an Active Directory account.

.DESCRIPTION
The Disable-ADAccount cmdlet disables an Active Directory user, computer, or service account.

The Identity parameter specifies the Active Directory user, computer service account, or other service account that you want to disable.
You can identify an account by its distinguished name (DN), GUID, security identifier (SID), or Security Accounts Manager (SAM) account name.
You can also set the Identity parameter to an object variable such as $<localADAccountObject>, or you can pass an account object through the pipeline to the Identity parameter.
For example, you can use the Get-ADUser cmdlet to retrieve a user account object and then pass the object through the pipeline to the Disable-Account cmdlet. Similarly, you can use Get-ADComputer and Search-ADAccount to retrieve account objects.

For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
-The cmdlet is run from an Active Directory provider drive.
-A default naming context or partition is defined for the AD LDS environment.
 To specify a default naming context for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service agent (DSA) object (nTDSDSA) for the AD LDS instance.

.EXAMPLE
AD-Generic-UsrDisable.ps1

.NOTES
Copyright (C) 2015 Ormer ICT

.LINK
https://technet.microsoft.com/en-us/library/ee617197.aspx

#>

[cmdletbinding()]
param (
    [parameter(mandatory=$false)]
    [string]$Operator,

    [parameter(mandatory=$false)]
    [string]$MachineGroup,

    [parameter(mandatory=$false)]
    [string]$TDNumber,

    [parameter(mandatory=$true)]
    [string]$KworkingDir,

    # Procedure vars
    [Parameter(Mandatory=$false)]
    [String] $UserName
)

#region StandardFramework
Import-Module -Name OrmLogging -Prefix 'Orm' -ErrorAction SilentlyContinue -ErrorVariable ImportModuleOrmLoggingError
if($ImportModuleOrmLoggingError)
{
    Write-Error "Unable to import the Ormer Logging Powershell Module"
    Write-Error "$($ImportModuleOrmLoggingError.Exception.Message)"
    Break
}
Import-Module -Name OrmToolkit -Prefix 'Orm' -ErrorAction SilentlyContinue -ErrorVariable ImportModuleOrmToolkitError
if($ImportModuleOrmToolkitError)
{
    Write-Error "Unable to import the Ormer Toolkit Powershell Module"
    Write-Error "$($ImportModuleOrmToolkitError.Exception.Message)"
    Break
}

Set-Location $KworkingDir -ErrorAction SilentlyContinue -ErrorVariable SetLocationError
if($SetLocationError)
{
    Write-Error "Unable to set the working directory of the script"
    Write-Error "$($SetLocationError.Exception.Message)"
    Break
}
    
$Domain = $env:USERDOMAIN
$MachineName = $env:COMPUTERNAME
$GetProcName = Get-PSCallStack
$procname = $GetProcname.Command
$Customer = $MachineGroep.Split('.')[2]


$logvar = New-Object -TypeName PSObject -Property @{
    'Domain' = $Domain 
    'MachineName' = $MachineName
    'procname' = $procname
    'Customer' = $Customer
    'Operator'= $Operator
    'TDNumber'= $TDNumber
}

Remove-Item "$KworkingDir\ProcedureLog.log" -Force -ErrorAction SilentlyContinue
New-OrmLog -logvar $logvar -Status 'Start' -LogDir $KworkingDir -Message "Starting procedure: $($procname)" -ErrorAction Stop
#endregion StandardFramework
    
#region Execution

#region Windows Server 2008

$Server2008 = [environment]::OSVersion | Select-Object -ExpandProperty Version | Where-Object {$_.Major -like "6" -and $_.Minor -like "0"}
if ($Server2008)
{
    New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Windows server 2008 detected, PowerShell Modules not supported"
    New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
    Break
}

#endregion Windows Server 2008

#region Load module Server manager
    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Checking to see if the servermanager PowerShell module is installed" -ErrorAction Stop
    if ((get-module -name servermanager -ErrorAction SilentlyContinue | foreach { $_.Name }) -ne "servermanager") {
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Adding servermanager PowerShell module" -ErrorAction Stop
        import-module servermanager
        }
    else {
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "servermanager PowerShell module is Already loaded" -ErrorAction Stop
        }
#endregion Load module Server manager

#region Install RSAT-AD-PowerShell
    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Check if RSAT-AD-PowerShell is installed" -ErrorAction Stop
    $RSAT = (Get-WindowsFeature -name RSAT-AD-PowerShell).Installed 

    If ($RSAT -eq $false) {
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "RSAT-AD-PowerShell not found: `'$($RSAT)`'" -ErrorAction Stop

        Add-WindowsFeature RSAT-AD-PowerShell
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Add Windows Feature RSAT-AD-PowerShell" -ErrorAction Stop

        Import-module ActiveDirectory
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Import module ActiveDirectory" -ErrorAction Stop
        }
    Else {
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Windows Feature RSAT-AD-PowerShell installed" -ErrorAction Stop
        }
#endregion Install RSAT-AD-PowerShell

#region Import Module Active Directory
    if ((get-module -name ActiveDirectory -ErrorAction SilentlyContinue | foreach { $_.Name }) -ne "ActiveDirectory") {
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Adding ActiveDirectory PowerShell module" -ErrorAction Stop
        import-module ActiveDirectory
        }
    else {
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "ActiveDirectory PowerShell module is Already loaded" -ErrorAction Stop
        }
#endregion Import Module Active Directory


if ($username.length -gt 15){
    $username = (get-aduser -filter {extensionattribute15 -like $username}).samaccountname
}

#region Disable Account
    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Disable user account: `'$($UserName)`'" -ErrorAction Stop
    Disable-ADAccount -Identity $UserName
#endregion Disable Account

#region end log
        New-OrmLog -logvar $logvar -status 'Success' -LogDir $KworkingDir -Message "END Title: $($Procname) Script" -ErrorAction Stop
$ssplog = "$Kworkingdir\$TDNumber.csv"
$ssplogvar = New-Object -TypeName PSObject -Property @{
'logID'=([guid]::NewGuid()).guid
'youweID'=$TDNumber
'sspUid'=$(get-aduser $username -prop extensionattribute15 |select -ExpandProperty extensionattribute15)
'action'= $myinvocation.mycommand.Name
'parameters'= (get-content $KworkingDir\param.txt -Tail 1)
'result'= $sspresult
'companyID'= $Kaseyagroup
'last_changed'= (get-aduser $nc_sam -prop whenchanged|select-object -expand whenchanged)
}
$ssplogvar|export-csv -Path $ssplog -Delimiter ";" -NoTypeInformation

#endregion End Log

    
#endregion Execution