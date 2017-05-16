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
    [String] $UserName,

    [Parameter(Mandatory=$false)]
    [String] $newUserName,

    [Parameter(Mandatory=$false)]
    [String] $FunctionGroup,

    [Parameter(Mandatory=$true)]
    [String] $SurName,

    [Parameter(Mandatory=$true)]
    [String] $GivenName,

    [Parameter(Mandatory=$false)]
    [String] $insertion,

    [Parameter(Mandatory=$false)]
    [String] $removeMail,
	
    [Parameter(Mandatory=$false)]
    [String] $addMail,

 	[Parameter(Mandatory=$false)]
    [string[]] $Functions,

	[Parameter(Mandatory=$false)]
    [String] $Department,

	[Parameter(Mandatory=$true)]
    [String] $Kaseyagroup
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

#region Change user account
$user = $false
if ($username.length -gt 15){
    $user = get-aduser -filter {extensionattribute15 -like $username}
    $username = $user.samaccountname
}
Else {
    $user = get-aduser $username
}

if ($user){
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "$username found"
    import-module ActiveDirectory
}
else{
    New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "$username is not found"
    Break
}

# Import XML
if ($insertion -eq "<none>"){$insertion=""}
[XML]$adsettings=get-content "$KworkingDir\$kaseyagroup.xml"
# Create vars
$NC_Name = Convert-formatstring -tring $adsettings.customer.NC_Name
$NC_DisplayName = Convert-formatstring -tring $adsettings.customer.NC_DisplayName
$NC_DisplayName = $NC_DisplayName.replace("  "," ")
$NC_SAM = Convert-formatstring -tring $adsettings.customer.NC_SAM
if ($Mail -eq "<None>"){
    $NC_Email = Convert-formatstring -tring $adsettings.customer.NC_Email
}

else {
    $NC_Email = $mail
}

if ($department -eq "<None>"){
    $NC_path = "$($adsettings.Customer.AD_userpath)"
    move-adobject -identity $user -Targetpath "$($adsettings.Customer.AD_userpath)"
    $result = "$Result Department: User to user OU;"
}
else {
    $NC_path = "OU=$($department),$($adsettings.Customer.AD_userpath)"
    $dep = $adsettings.customer.departments.department |where-object name -like "$department"
    if ($NC_email -notlike "*@*"){$NC_Email = "$($NC_Email)@$($dep.SMTPDomain)"}
    move-adobject -identity $user -Targetpath $NC_path
}

if ($removemail -like "*@*"){
    $user |set-aduser -remove @{proxyaddresses="smtp:$removemail"}
    $result = "$Result Removemail $removemail;"
}
if ($addmail -like "*@*"){
    $user |set-aduser -add @{proxyaddresses="smtp:$addmail"}
    $result = "$Result Addmail $addmail;"
}


if ($newusername -eq "<None>"){
    $user |set-aduser -SamAccountName $NC_SAM
    $result = "$result Samaccountname changed to default $NC_SAM;"
}
Else{
    if ($newusername -ne $username){
        $user| Set-aduser -SamAccountName $newusername
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Username $username changed into $newusername"
        $result = "$result Username $username changed into $newusername;"
    }
}
if ($surname -ne $user.surname){
    $user |set-aduser -Surname $surname
    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Surname $($user.surname) changed into $surname"
    $result = "$result Surname $($user.surname) changed into $surname;"
}
if ($insertion -eq "<None>"){
    $user |set-aduser -DisplayName $NC_DisplayName
    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Insertion removed"
    $result = "$result Insertion removed;"
}
if ($givenname -ne $user.GivenName){
    $user |set-aduser -givenname $givenname
    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Given name $($user.givenname) changed into $givenname"
    $result = "$result Given name $($user.givenname) changed into $givenname;"
}
if ($NC_DisplayName -ne $user.displayname){
    $user |set-aduser -displayname $NC_DisplayName
    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Display name $($user.displayname) changed into $nc_displayname"
    $result = "$result Display name $($user.displayname) changed into $nc_displayname;"
}
#endregion Change user account
#region Add to group

ForEach ($Function in $Functions){
    Add-ADGroupMember -identity $Function -Members $username -ErrorAction Stop
}

#endregion Add to group

    New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"

#startregion ssplog
$ssplog = "$Kworkingdir\$TDNumber.csv"
$ssplogvar = New-Object -TypeName PSObject -Property @{
'logID'=([guid]::NewGuid()).guid
'youweID'=$TDNumber
'sspUid'=$($user.extensionattribute15)
'action'= $myinvocation.mycommand.Name
'parameters'= (get-content $KworkingDir\param.txt -Tail 1)
'result'= $sspresult
'companyID'= $Kaseyagroup
'last_changed'= (get-aduser $nc_sam -prop whenchanged|select-object -expand whenchanged)
}
$ssplogvar|export-csv -Path $ssplog -Delimiter ";" -NoTypeInformation

#endregion ssplog


#endregion Execution
