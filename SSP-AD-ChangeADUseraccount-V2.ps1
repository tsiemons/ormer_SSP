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
    [String] $Username,

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
    [String] $PrimaryMail,
	
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
$Server2008 = [environment]::OSVersion | Select-Object -ExpandProperty Version | Where-Object { $_.Major -like "6" -and $_.Minor -like "0" }
if ($Server2008)
{
	New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Windows server 2008 detected, PowerShell Modules not supported"
	$sspresult = "Mislukt|Server 2008 wordt niet ondersteund"
	$ProcedureFailed = $true
}
#endregion Windows Server 2008

#region Load ActiveDirectory PowerShell Module
if ($ProcedureFailed -ne $true)
{
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Checking if ActiveDirectory PowerShell module is installed..."
	if ((Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue) -eq $null)
	{
		New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "ActiveDirectory PowerShell module is not installed."
		$sspresult = "Mislukt|ActiveDirectory PowerShell module is niet geïnstalleerd"
		$ProcedureFailed = $true
	}
	else
	{
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "ActiveDirectory PowerShell module is installed."
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Checking if ActiveDirectory PowerShell module is currently imported..."
		if ((Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue) -eq $null)
		{
			New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "ActiveDirectory PowerShell module is not currently imported."
			New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Importing ActiveDirectory PowerShell module..."
			Import-Module ActiveDirectory -ErrorAction SilentlyContinue -ErrorVariable ImportModuleError
			if ($ImportModuleError)
			{
				$sspresult = ('Mislukt|ActiveDirectory PowerShell module kon niet worden geladen vanwege de volgende fout: [{0}]' -f ($ImportModuleError[0].Exception.Message -replace "\r\n", ". "))
				$ProcedureFailed = $true
			}
			else
			{
				New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -Message "Successfully imported ActiveDirectory PowerShell module."
			}
		}
		else
		{
			New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "ActiveDirectory PowerShell module is currently imported."
		}
	}
}
#endregion

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

function Convert-FormatString
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[string]$String
	)
	
	Switch -Regex ($String)
	{
		"%G\d+"{
			$n = $String | select-string -pattern "%G\d+" -AllMatches
			$n.matches.value | foreach-object {
				[int]$number = (select-string -input $_ -pattern "\d+").Matches.value
				$givenname = $givenname.substring(0, [int]$number)
				$String = $String.replace("$_", "$givenname")
			}
		}
		"%G"{ $String = $String.replace("%G", "$givenname") }
		"%S\d+"{
			$n = $String | select-string -pattern "%S\d+" -AllMatches
			$n.matches.value | foreach-object {
				[int]$number = (select-string -input $_ -pattern "\d+").Matches.value
				$surname = $surname.substring(0, [int]$number)
				$String = $String.replace("$_", "$surname")
			}
		}
		"%S"{ $String = $String.replace("%S", "$surname") }
		"%I\d+"{
			$n = $String | select-string -pattern "%I\d+" -AllMatches
			$n.matches.value | foreach-object {
				[int]$number = (select-string -input $_ -pattern "\d+").Matches.value
				$givenname = $givenname.substring(0, [int]$number)
				$String = $String.replace("$_", "$givenname")
			}
		}
		"%I"{ $String = $String.replace("%I", "$insertion") }
	}
	$String
}

function Test-EmailAddress
{
<#
	.SYNOPSIS
		Tests if a specified SMTP-address exists in an Active Directory Domain.
	
	.DESCRIPTION
		Tests if a specified SMTP-address exists in an Active Directory Domain. Returns a boolean value.
	
	.PARAMETER EmailAddress
		The e-mailaddress to test for existance
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	[OutputType([bool])]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$EmailAddress
	)
	
	Process
	{
		# Get All Mail-enabled AD Objects		
		$MailObjects = Get-ADObject -Properties mail, proxyAddresses -Filter { (mail -like "*") -or (proxyAddresses -like "*") } -ErrorAction Stop
		
		# Check if the E-mailaddress exists
		$Match = $MailObjects | Where-Object -FilterScript { $_.mail -eq $EmailAddress -or $_.proxyAddresses -match ('^(smtp:)+({0})$' -f $EmailAddress.Replace('.', '\.')) }
		
		if ($Match)
		{
			Write-Output -InputObject $true
		}
		else
		{
			Write-Output -InputObject $false
		}
	}
}
#endregion functions

#region Change user account
$User = $false
if ($Username.length -gt 15){
    $User = get-aduser -filter { extensionattribute15 -like $Username } -Properties extensionattribute14, extensionattribute15, proxyaddresses
    $Username = $User.samaccountname
}
else
{
    $User = get-aduser $Username -Properties extensionattribute14,extensionattribute15,proxyaddresses
}

if ($User)
{
    New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "$Username found"    
}
else
{
    New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "$Username is not found"
    Break
}

# Import XML
[XML]$adsettings=get-content "$KworkingDir\$kaseyagroup.xml"
#generate vars
$companyid = $adsettings.customer.companyguid
if (($surname -ne $User.surname) -or ($insertion -eq "<none>") -or ($insertion -ne $User.extensionattribute14) -or ($givenname -ne $User.GivenName) -or ($newusername -ne $User.samaccountname)){
    if ($insertion -eq "<none>"){
        $insertion = ""
        $User |set-aduser -clear extensionattribute14 -ErrorVariable Aderror
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Removed insertion"
        $sspresult = "$sspresult Removed insertion;"
    }
    #$NC_Name = Convert-formatstring -tring $adsettings.customer.NC_Name

    if ($insertion -ne $User.extentionattribute14){
        $User |set-aduser -replace @{extensionattribute14=$insertion} -ErrorVariable aderror
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "insertion $($User.extensionattribute14) changed into $insertion"
        $sspresult = "$sspresult insertion $($User.extensionattribute14) changed into $insertion;"
    }

    if ($givenname -ne $User.GivenName){
        $User |set-aduser -givenname $givenname -ErrorVariable
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Given name $($User.givenname) changed into $givenname"
        $sspresult = "$sspresult Given name $($User.givenname) changed into $givenname;"
    }

    if ($surname -ne $User.surName){
        $User |set-aduser -surname $surname -ErrorVariable aderror
        New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Given name $($User.surname) changed into $surname"
        $sspresult = "$sspresult Given name $($User.surname) changed into $surname;"
    }

    if ($newusername -ne $User.samaccountname){
        if ($newusername -eq "<none>" ){
            $NC_SAM = Convert-FormatString -String $adsettings.customer.NC_sam
            $Username = $NC_SAM
            $User |set-aduser -SamAccountName $NC_SAM -ErrorVariable aderror
            $User = get-aduser $NC_SAM -Properties extensionattribute14,extensionattribute15,proxyaddresses -ErrorVariable aderror
            New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "login $($User.samaccountname) changed into $NC_SAM"
            $sspresult = "$sspresult login $($User.samaccountname) changed into $newusername;"
        }
        Else{
            $User |set-aduser -SamAccountName $newusername
            $User = get-aduser $newusername -Properties extensionattribute14,extensionattribute15,proxyaddresses -ErrorVariable aderror
            $Username = $newusername
            New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "login $($User.samaccountname) changed into $newusername"
            $sspresult = "$sspresult login $($User.samaccountname) changed into $newusername;"
        }
    }

    $NC_DisplayName = Convert-FormatString -String $adsettings.customer.NC_DisplayName
    $NC_DisplayName = $NC_DisplayName.replace("  "," ")
    $User |set-aduser -DisplayName $NC_DisplayName -ErrorVariable aderror

    if ($primaryMail -eq "<None>"){
        $NC_Email = Convert-FormatString -String $adsettings.customer.NC_Email
        if ($department -eq "<None>"){
            $primarymail = "$($NC_Email)@$($adsettings.Customer.SMTPDomain)"
        }
        else {
            $dep = $adsettings.customer.departments.department |where-object name -like "$department"
            $primarymail = "$($NC_Email)@$($dep.SMTPDomain)"
        }
    }
}


if ($department -eq "<None>"){
    $NC_path = "$($adsettings.Customer.AD_userpath)"
    move-adobject -identity $User.distinguishedname -Targetpath "$($adsettings.Customer.AD_userpath)" -confirm:$false -ErrorVariable aderror
    $sspresult = "$sspresult Department: User to user OU;"
}
else {
    $NC_path = "OU=$($department),$($adsettings.Customer.AD_userpath)"
    $dep = $adsettings.customer.departments.department |where-object name -like "$department"
    if ($NC_email -notlike "*@*"){$NC_Email = "$($NC_Email)@$($dep.SMTPDomain)"}
    move-adobject -identity $User.distinguishedname -Targetpath $NC_path -confirm:$false -ErrorVariable aderror
}
if ($primarymail -like "*@*"){
    $primarymail = $primarymail.tolower()
    $addresses = @()
    if ($User.proxyaddresses -match "SMTP:$primarymail"){
        foreach ($address in $User.proxyaddresses){
            if ($address -eq "smtp:$primarymail"){
                $tempaddress = $address -replace "smtp:","SMTP:"
                $addresses += $tempaddress    
            }
            Else{
                $tempaddress = $address -replace "smtp:","smtp:"
                $addresses += $tempaddress
            }
        }
        $sspresult = "$sspresult Primaryemail exists is made primary;"
    }
    Else{
        foreach ($address in $User.proxyaddresses){
                $tempaddress = $address -replace "smtp:","smtp:"
                $addresses += $tempaddress
            }
        $addresses += "SMTP:$primarymail"
    }
    $User |set-aduser -replace @{proxyaddresses=$addresses} -userprincipalname $primarymail -emailaddress $primarymail -ErrorVariable aderror
    $sspresult = "$sspresult Primarymail $primarymail;"
}

if ($removemail -like "*@*"){
    $removemail = $removemail.tolower()
    if ($User.proxyaddresses -cmatch "SMTP:$removemail"){
        $sspresult = "$sspresult Failed, Removemail $removemail is primary;"
    }
    Else{
        $User |set-aduser -remove @{proxyaddresses="smtp:$removemail"} -ErrorVariable aderror
        $sspresult = "$sspresult Removemail $removemail;"
    }
}
if ($addmail -like "*@*"){
    $addmail=$addmail.tolower()
    $User |set-aduser -add @{proxyaddresses="smtp:$addmail"} -ErrorVariable aderror
    $sspresult = "$sspresult Addmail $addmail;"
}


#endregion Change user account
#region Add to group
$functiongroups = get-adgroup -searchbase "$($adsettings.Customer.AD_functionpath)" -filter *
Foreach ($functiongroup in $functiongroups)
{
    $functiongroup | remove-adgroupmember -members $User.sid -confirm:$false
}

ForEach ($Function in $Functions)
{
    Add-ADGroupMember -identity $Function -Members $Username -ErrorAction Stop
}

#endregion Add to group
New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "$sspresult"
New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "END title: $procname Script"

if ($aderror.length -gt 0)
{
    $sspresult = "Mislukt|Account $Username is niet of maar gedeeltelijk aangepast $aderror"
}
else
{
    $sspresult = "Gereed|Account $Username is aangepast"
}

#startregion ssplog
$ssplog = "$Kworkingdir\$TDNumber.csv"
$ssplogvar = New-Object -TypeName PSObject -Property @{
'logID'=([guid]::NewGuid()).guid
'youweID'=$TDNumber
'sspUid'=$(get-aduser $Username -prop extensionattribute15 -erroraction SilentlyContinue | Select-Object -ExpandProperty extensionattribute15)
'action'= "Account aanpassing"
'parameters'= (get-content $KworkingDir\param.txt -Tail 1)
'result'= $sspresult
'companyID'= $Companyid
'last_changed'= get-date (get-aduser $Username -prop whenchanged -ErrorAction SilentlyContinue| Select-object -expand whenchanged) -f "dd-MM-yyyy hh:mm:ss"
}
$ssplogvar|export-csv -Path $ssplog -Delimiter ";" -NoTypeInformation

#endregion ssplog


#endregion Execution
