<#

.SYNOPSIS
Modifies the password of an Active Directory account.

.DESCRIPTION
The Set-ADAccountPassword cmdlet sets the password for a user, computer or service account.

The Identity parameter specifies the Active Directory account to modify.
You can identify an account by its distinguished name (DN), GUID, security identifier (SID) or security accounts manager (SAM) account name.
You can also set the Identity parameter to an object variable such as $<localADAccountObject>, or you can pass an object through the pipeline to the Identity parameter.
For example, you can use the Search-ADAccount cmdlet to retrieve an account object and then pass the object through the pipeline to the Set-ADAccountPassword cmdlet.
Similarly, you can use Get-ADUser, Get-ADComputer or Get-ADServiceAccount cmdlets to retrieve account objects that you can pass through the pipeline to this cmdlet.

You must set the OldPassword and the NewPassword parameters to set the password unless you specify the Reset parameter.
When you specify the Reset parameter, the password is set to the NewPassword value that you provide and the OldPassword parameter is not required.

For AD LDS environments, the Partition parameter must be specified except in the following two conditions:
-The cmdlet is run from an Active Directory provider drive.
-A default naming context or partition is defined for the AD LDS environment.
 To specify a default naming context for an AD LDS environment, set the msDS-defaultNamingContext property of the Active Directory directory service agent (DSA) object (nTDSDSA) for the AD LDS instance.

.EXAMPLE
AD-Generic-UsrResetPassword.ps1

.NOTES
Copyright (C) 2015 Ormer ICT

Date (DD/MM/YYYY)   Name             Description
21/08/2015          Jeff Wouters     Made authentication work by moving 'Change pwd at logon' after authentication

.LINK
https://technet.microsoft.com/en-us/library/ee617261.aspx

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
	[Parameter(Mandatory = $true)]
	[String]$KaseyaGroup,
    [Parameter(Mandatory=$true)]
	[String]$Username,
	[Parameter(Mandatory = $true)]
	[String]$Password
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
$Procname = $MyInvocation.MyCommand.Name
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
New-OrmLog -logvar $logvar -Status 'Start' -LogDir $KworkingDir -ErrorAction Stop -Message "Starting procedure: $($procname)"
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

New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Checking to see if the servermanager PowerShell module is installed"
if (get-module -name servermanager -ErrorAction SilentlyContinue)
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Adding servermanager PowerShell module"
    import-module servermanager
}
else
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "servermanager PowerShell module is Already loaded"
}

#endregion Load module Server manager

#region Install RSAT-AD-PowerShell

New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Check if RSAT-AD-PowerShell is installed"
$RSAT = Get-WindowsFeature -name RSAT-AD-PowerShell | Select-Object -ExpandProperty Installed 

if ($RSAT -eq $false)
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "RSAT-AD-PowerShell not found: $($RSAT)"
    Add-WindowsFeature RSAT-AD-PowerShell
    New-OrmLog -logvar $logvar -status 'start' -LogDir $KworkingDir -Message "Add Windows Feature RSAT-AD-PowerShell"
    Import-module ActiveDirectory
    New-OrmLog -logvar $logvar -status 'Start' -LogDir $KworkingDir -Message "Import module ActiveDirectory"
}
else
{
    New-OrmLog -logvar $logvar -status 'start' -LogDir $KworkingDir -Message "Windows Feature RSAT-AD-PowerShell installed"
    Import-module ActiveDirectory
    New-OrmLog -logvar $logvar -status 'Start' -LogDir $KworkingDir -Message "Import module ActiveDirectory"
}

#endregion Install RSAT-AD-PowerShell

#region Import Module Active Directory
if (Get-Module -Name ActiveDirectory -listAvailable)
{
    if (get-module -name ActiveDirectory -ErrorAction SilentlyContinue)
    {
        New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Adding ActiveDirectory PowerShell module"
        import-module ActiveDirectory
    }
    else
    {
        New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "ActiveDirectory PowerShell module is Already loaded"
    }
}
else
{
    New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "No ActiveDirectory PowerShell module found on the system"
    New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
    Break    
}

#endregion Import Module Active Directory

#region Check if user is disabled

if ($username.length -gt 15){
    $username = (get-aduser -filter {extensionattribute15 -like $username}).samaccountname
}

$UserEnabled = Get-ADUser -Identity $UserName | Select-Object -ExpandProperty Enabled
if ($UserEnabled -eq $false)
{
    New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "User is disabled, please contact the manager"
    New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
    Break
}
else
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "User is enabled: $($UserName)"
}

#endregion Check if user is disabled

#region create password

Function New-RandomComplexPassword
{
    param ( [int]$Length = 8 )
    #Usage: New-RandomComplexPassword 12
    try {
        $Assembly = Add-Type -AssemblyName System.Web
        $RandomComplexPassword = [System.Web.Security.Membership]::GeneratePassword($Length,2)
        Write-Output $RandomComplexPassword
    }
    catch
    {
        Write-Error $_
    }
}

#$password = New-RandomComplexPassword -Length (Get-ADDefaultDomainPasswordPolicy | Select-Object -ExpandProperty MinPasswordLength)

#endregion create password

#region reset password

New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Reset user password"
try
{
    Set-ADAccountPassword -identity $UserName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -ErrorAction SilentlyContinue -ErrorVariable setadacccountpassworderror
}
catch
{
    $setadacccountpassworderror = $_.Exception
}

if ($setadacccountpassworderror)
{
    New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Error occured setting the AD password"
    New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message $setadacccountpassworderror.Message
    New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
    $aderror += $setadacccountpassworderror
    Break
}
else
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "New AD User PassWord is set"
    $sspresult = "Set password succeeded"
}

try {
    Set-ADuser -identity $UserName -PasswordNeverExpires $false -ErrorAction SilentlyContinue -ErrorVariable setadusererror
}
catch
{
    $setadusererror = $_.Exception
}
if ($setadusererror)
{
    New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message $setadusererror.Message
    New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
    Break
}
else
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Change PassWord At Next logon is set for $($UserName)"
    
}
try
{
    Unlock-ADAccount -Identity $UserName -ErrorAction SilentlyContinue -ErrorVariable ADerror
}
catch
{
    $unlockadaccounterror = $_.Exception
}
if ($unlockadaccounterror)
{
    New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Failed to unlock AD user account"
    New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message $unlockadaccounterror.Message
    New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
    Break
}
else
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "AD User Accound is unlocked"
}

#endregion reset password

#region Test user login

Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorVariable err -ErrorAction SilentlyContinue
if ($err)
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Faild to test authentication" -ErrorAction Stop
}
else
{
    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ct,$Domain -ErrorVariable err -ErrorAction SilentlyContinue
    if ($err)
    {
        New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Faild to test authentication"
        New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
        Break
    }
    if ($pc.ValidateCredentials($UserName,$password))
    {
        New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Authentication successfully"
        try {
            Set-ADuser -Identity $UserName -ChangePasswordAtLogon $true -ErrorAction SilentlyContinue -ErrorVariable ADError
            New-OrmLog -logvar $logvar -Status 'Success' -LogDir $KworkingDir -ErrorAction Stop -Message "Successfully set Change PassWord At Next logon"
        }
        catch
        {
            New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Failed to set Change PassWord At Next logon"
            break
        }
        if ($ChangePwdAtLogonError)
        {
            New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Error encountered when setting Change PassWord At Next logon"
            break
        }
    }
    else
    {
        New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Authentication not successful"
        New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
        Break
    }
}
    

#endregion Test user login
if ($aderror.length -gt 0){
    $sspresult = "Mislukt|$username wachtwoord verandering is niet gelukt $aderror"
}
Else{
    $sspresult = "Gereed|$username heeft een nieuw wachtwoord"
}

New-OrmLog -logvar $logvar -Status 'Success' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
[XML]$adsettings=get-content "$KworkingDir\$kaseyagroup.xml"
$companyid = $adsettings.customer.companyguid

$ssplog = "$Kworkingdir\$TDNumber.csv"
$ssplogvar = New-Object -TypeName PSObject -Property @{
'logID'=([guid]::NewGuid()).guid
'youweID'=$TDNumber
'sspUid'=$(get-aduser $UserName -prop extensionattribute15 -erroraction SilentlyContinue |Select-Object -ExpandProperty extensionattribute15)
'action'= $myinvocation.mycommand.Name
'parameters'= (get-content $KworkingDir\param.txt -Tail 1)
'result'= $sspresult
'companyID'= $Companyid
'last_changed'= get-date (get-aduser $username -prop whenchanged -ErrorAction SilentlyContinue|select-object -expand whenchanged) -f "dd-MM-yyyy hh:mm:ss"
}
$ssplogvar|export-csv -Path $ssplog -Delimiter ";" -NoTypeInformation
#endregion Execution