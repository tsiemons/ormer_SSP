﻿<#

.SYNOPSIS
Enables an Active Directory account.

.DESCRIPTION
The Enable-ADAccount cmdlet enables an Active Directory user, computer or service account.

The Identity parameter specifies the Active Directory user, computer or service account that you want to enable.
You can identify an account by its distinguished name (DN), GUID, security identifier (SID) or Security Accounts Manager (SAM) account name.
You can also set the Identity parameter to an object variable such as $<localADAccountObject>, or you can pass an account object through the pipeline to the Identity parameter.
For example, you can use the Get-ADUser cmdlet to retrieve an account object and then pass the object through the pipeline to the Enable-ADAccount cmdlet.
Similarly, you can use Get-ADComputer and Search-ADAccount to retrieve account objects.

.EXAMPLE
AD-Generic-UsrEnable.ps1

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
$Customer = $MachineGroup.Split('.')[2]


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
        New-OrmLog -logvar $logvar -status 'start' -LogDir $KworkingDir -Message "Add Windows Feature RSAT-AD-PowerShell" -ErrorAction Stop

        Import-module ActiveDirectory
        New-OrmLog -logvar $logvar -status 'Start' -LogDir $KworkingDir -Message "Import module ActiveDirectory" -ErrorAction Stop
        }
    Else {
        New-OrmLog -logvar $logvar -status 'start' -LogDir $KworkingDir -Message "Windows Feature RSAT-AD-PowerShell installed" -ErrorAction Stop
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

#region Check if user is disabled

    if ($username.length -gt 15){
        $username = (get-aduser -filter {extensionattribute15 -like $username}).samaccountname
    }

    $UserEnabled = (Get-ADUser -Identity $UserName).Enabled
    If ($UserEnabled -eq $false) {
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "User is disabled" -ErrorAction Stop
        }
    else {
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "User is enabled: `'$($UserName)`'" -ErrorAction Stop
        }

#endregion Check if user is disabled

#region Unlock Account

    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Enable user account: `'$($UserName)`'" -ErrorAction Stop
    Enable-ADAccount -Identity $UserName

#endregion Unlock Account

New-OrmLog -logvar $logvar -status 'Success' -LogDir $KworkingDir -Message "END title: $procname Script" -ErrorAction Stop

#endregion Execution