<#

.SYNOPSIS
Creates a new Active Directory user.

.DESCRIPTION
The New-ADUser cmdlet creates a new Active Directory user. You can set commonly used user property values by using the cmdlet parameters.

Property values that are not associated with cmdlet parameters can be set by using the OtherAttributes parameter.
When using this parameter be sure to place single quotes around the attribute name as in the following example.

New-ADUser -SamAccountName "glenjohn" -GivenName "Glen" -Surname "John" -DisplayName "Glen John" -Path 'CN=Users,DC=fabrikam,DC=local' -OtherAttributes @{'msDS-PhoneticDisplayName'="GlenJohn"}

You must specify the SAMAccountName parameter to create a user.

You can use the New-ADUser cmdlet to create different types of user accounts such as iNetOrgPerson accounts.
To do this in AD DS, set the Type parameter to the LDAP display name for the type of account you want to create.
This type can be any class in the Active Directory schema that is a subclass of user and that has an object category of person.

The Path parameter specifies the container or organizational unit (OU) for the new user.
When you do not specify the Path parameter, the cmdlet creates a user object in the default container for user objects in the domain. 

Accounts created with the New-ADUser cmdlet will be disabled if no password is provided.

The following methods explain different ways to create an object by using this cmdlet.

Method 1: Use the New-ADUser cmdlet, specify the required parameters, and set any additional property values by using the cmdlet parameters.

Method 2: Use a template to create the new object.
To do this, create a new user object or retrieve a copy of an existing user object and set the Instance parameter to this object.
The object provided to the Instance parameter is used as a template for the new object. You can override property values from the template by setting cmdlet parameters.
For examples and more information, see the Instance parameter description for this cmdlet.

Method 3: Use the Import-CSV cmdlet with the New-ADUser cmdlet to create multiple Active Directory user objects.
To do this, use the Import-CSV cmdlet to create the custom objects from a comma-separated value (CSV) file that contains a list of object properties.
Then pass these objects through the pipeline to the New-ADUser cmdlet to create the user objects.

.EXAMPLE
AD-Generic-NewADUserAccount.ps1

.NOTES
Copyright (C) 2015 Ormer ICT

.LINK
https://technet.microsoft.com/en-us/library/ee617253.aspx

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
    [String] $kaseyagroup,

    [Parameter(Mandatory=$true)]
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
if ((get-module -name servermanager -ErrorAction SilentlyContinue | foreach { $_.Name }) -ne "servermanager")
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
$RSAT = (Get-WindowsFeature -name RSAT-AD-PowerShell).Installed 

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
}

#endregion Install RSAT-AD-PowerShell

#region Import Module Active Directory

    if ((get-module -name ActiveDirectory -ErrorAction SilentlyContinue | foreach { $_.Name }) -ne "ActiveDirectory") {
        New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Adding ActiveDirectory PowerShell module"
        import-module ActiveDirectory
        }
    else {
        New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "ActiveDirectory PowerShell module is Already loaded"
        }

#endregion Import Module Active Directory

foreach ($in in $group){
    
}
#region functions

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

Function Convert-formatstring
{
[cmdletbinding()]
param (
    [parameter(mandatory=$false)]
    [string]$tring
)
    Switch -Regex ($tring)
    {
        "%G\d+"{
            $n=$tring |select-string -pattern "%G\d+" -AllMatches
            $n.matches.value|foreach-object {
            [int]$number = (select-string -input $_ -pattern "\d+").Matches.value
            $givenname = $givenname.substring(0,[int]$number)
            $tring=$tring.replace("$_","$givenname")
            }
        }
        "%G"{$tring=$tring.replace("%G","$givenname")}
        "%S\d+"{
            $n=$tring |select-string -pattern "%S\d+" -AllMatches
            $n.matches.value|foreach-object {
            [int]$number = (select-string -input $_ -pattern "\d+").Matches.value
            $surname = $surname.substring(0,[int]$number)
            $tring=$tring.replace("$_","$surname")
            }
        }
        "%S"{$tring=$tring.replace("%S","$surname")}
        "%I\d+"{
            $n=$tring |select-string -pattern "%I\d+" -AllMatches
            $n.matches.value|foreach-object {
            [int]$number = (select-string -input $_ -pattern "\d+").Matches.value
            $givenname = $givenname.substring(0,[int]$number)
            $tring=$tring.replace("$_","$givenname")
            }
        }
        "%I"{$tring=$tring.replace("%I","$insertion")}
    }
    $tring
}

#endregion functions

#region Remove user account

# Import XML
[XML]$adsettings=get-content "$KworkingDir\$kaseyagroup.xml"
$companyid = $adsettings.customer.companyguid


#set additional proprties
if ($username.length -gt 15){
    $username = (get-aduser -filter {extensionattribute15 -like $username}).samaccountname
}
$sspUid="$(get-aduser $UserName -prop extensionattribute15 -erroraction SilentlyContinue |Select-Object -ExpandProperty extensionattribute15)"
$whenchanged = get-date (get-aduser $username -prop whenchanged -ErrorAction SilentlyContinue|select-object -expand whenchanged) -f "dd-MM-yyyy hh:mm:ss"

    Get-ADUser $username | remove-aduser -confirm:$false -ErrorVariable aderror
    if ($aderror.length -gt 0){
        $sspresult = "Mislukt| $username niet verwijderd $aderror"
    }
    Else{
        $sspresult = "Gereed| $username verwijderd"
    }
    

#region Add to group

#endregion Add to group
 
 
New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"
$ssplog = "$Kworkingdir\$TDNumber.csv"
$ssplogvar = New-Object -TypeName PSObject -Property @{
'logID'=([guid]::NewGuid()).guid
'youweID'=$TDNumber
'sspUid'=$sspuid
'action'= "Account verwijderen"
'parameters'= (get-content $KworkingDir\param.txt -Tail 1)
'result'= $sspresult
'companyID'= $Companyid
'last_changed'= $whenchanged
}
$ssplogvar|export-csv -Path $ssplog -Delimiter ";" -NoTypeInformation

#endregion Execution