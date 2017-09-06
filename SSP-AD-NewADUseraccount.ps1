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
	[parameter(mandatory = $false)]
	[string]$Operator,
	[parameter(mandatory = $false)]
	[string]$MachineGroup,
	[parameter(mandatory = $false)]
	[string]$TDNumber,
	[parameter(mandatory = $true)]
	[string]$KworkingDir,
	# Procedure vars

	[Parameter(Mandatory = $false)]
	[String]$UserName,
	[Parameter(Mandatory = $true)]
	[String]$SurName,
	[Parameter(Mandatory = $false)]
	[String]$insertion,
	[Parameter(Mandatory = $true)]
	[String]$GivenName,
	[Parameter(Mandatory = $false)]
	[String]$Mail,
	[Parameter(Mandatory = $false)]
	[String]$Functions,
	[Parameter(Mandatory = $true)]
	[String]$SspUid,
	[Parameter(Mandatory = $true)]
	[String]$passwd,
	[Parameter(Mandatory = $true)]
	[String]$Kaseyagroup,
	[Parameter(Mandatory = $false)]
	[String]$Department
)

#region StandardFramework
Start-Transcript -Path $KworkingDir\trans.txt
Import-Module -Name OrmLogging -Prefix 'Orm' -ErrorAction SilentlyContinue -ErrorVariable ImportModuleOrmLoggingError
if ($ImportModuleOrmLoggingError)
{
	Write-Error "Unable to import the Ormer Logging Powershell Module"
	Write-Error "$($ImportModuleOrmLoggingError.Exception.Message)"
	Break
}
Import-Module -Name OrmToolkit -Prefix 'Orm' -ErrorAction SilentlyContinue -ErrorVariable ImportModuleOrmToolkitError
if ($ImportModuleOrmToolkitError)
{
	Write-Error "Unable to import the Ormer Toolkit Powershell Module"
	Write-Error "$($ImportModuleOrmToolkitError.Exception.Message)"
	Break
}

Set-Location $KworkingDir -ErrorAction SilentlyContinue -ErrorVariable SetLocationError
if ($SetLocationError)
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
	'Operator' = $Operator
	'TDNumber' = $TDNumber
}

Remove-Item "$KworkingDir\ProcedureLog.log" -Force -ErrorAction SilentlyContinue
New-OrmLog -logvar $logvar -Status 'Start' -LogDir $KworkingDir -ErrorAction Stop -Message "Starting procedure: $($procname)"
#endregion StandardFramework

#region Functions
Function New-RandomComplexPassword
{
	param ([int]$Length = 8)
	#Usage: New-RandomComplexPassword 12
	try
	{
		$Assembly = Add-Type -AssemblyName System.Web
		$RandomComplexPassword = [System.Web.Security.Membership]::GeneratePassword($Length, 2)
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

#region Create user account
if ($ProcedureFailed -ne $true)
{
	Try
	{
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Generating values for the new user account..."
		
		$insertionprop = $insertion
		if ($insertion -eq "<None>")
		{
			$insertion = ""
		}
		
		# Import XML
		[XML]$adsettings = Get-Content -Path "$KworkingDir\$kaseyagroup.xml" -ErrorAction Stop
		$companyid = $adsettings.customer.companyguid
		#$NewPassword = New-RandomComplexPassword -Length (Get-ADDefaultDomainPasswordPolicy | Select-Object -ExpandProperty MinPasswordLength)
		
		# Create vars
		$NC_Name = Convert-FormatString -String $adsettings.customer.NC_Name		
		
		$NC_DisplayName = Convert-FormatString -String $adsettings.customer.NC_DisplayName
		$NC_DisplayName = $NC_DisplayName.replace("  ", " ")
		
		if ($username -eq "<None>")
		{
			$NC_SAM = Convert-FormatString -String $adsettings.customer.NC_SAM
		}
		else
		{
			$NC_SAM = $username
		}
		
		if ($Mail -eq "<None>")
		{
			$NC_Email = Convert-FormatString -String $adsettings.customer.NC_Email
		}
		else
		{
			$NC_Email = $mail
		}
		
		if ($department -eq "<None>")
		{
			$NC_path = "$($adsettings.Customer.AD_userpath)"
			if ($NC_email -notlike "*@*")
			{
				$NC_Email = "$($NC_Email)@$($adsettings.Customer.SMTPDomain)"
			}
		}
		else
		{
			$NC_path = "OU=$($department),$($adsettings.Customer.AD_userpath)"
			$dep = $adsettings.customer.departments.department | Where-Object -FilterScript { name -like "$department" }
			if ($NC_email -notlike "*@*")
			{
				$NC_Email = "$($NC_Email)@$($dep.SMTPDomain)"
			}
		}
		# Hier moet nog via Department het juiste SMTPDomain worden gekozen	
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Values for the new user account generated successfully."
	}
	Catch
	{
		New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Failed to generate values for the new user account."
		$sspresult = ('Mislukt|Fout tijdens het genereren van de waardes voor het gebruikersaccount: [{0}]' -f ($_.Exception.Message -replace "\r\n", ". "))
		$ProcedureFailed = $true
	}
}

#region Peform Tests before creating user account

# Test if AD User Account already exists
New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Testing if AD User [{0}] already exists..." -f $NC_SAM)
if ((Get-ADUser -Filter { SamAccountName -eq $NC_SAM } -ErrorAction SilentlyContinue) -ne $null)
{
	New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message ("AD User [{0}] already exists." -f $NC_SAM)
	$sspresult = ('Mislukt|Aan te maken gebruikersnaam [{0}] bestaat al' -f $NC_SAM)
	$ProcedureFailed = $true
}
else
{
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("AD User [{0}] does not exist." -f $NC_SAM)
}

# Test if e-mailaddress already exists
New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Testing if e-mail address [{0}] already exists..." -f $NC_Email)
if ((Test-EmailAddress -EmailAddress $NC_Email) -eq $true)
{
	New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message ("E-mail address [{0}] already exists." -f $NC_Email)
	if ($sspresult -ne $null)
	{
		$sspresult += (', aan te maken E-mailadres [{0}] bestaat al' -f $NC_Email)
	}
	else
	{
		$sspresult = ('Mislukt|Aan te maken E-mailadres [{0}] bestaat al' -f $NC_Email)	
	}	
	$ProcedureFailed = $true
}
else
{
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("E-mail address [{0}] does not exist." -f $NC_Email)
}
#endregion

if ($ProcedureFailed -ne $true)
{
	Try
	{
		# Create a hashtable with the parameters used by the New-ADUser cmdlet
		$Properties = @{
			'Name' = $NC_Name
			'GivenName' = $GivenName
			'Initials' = $insertion
			'Surname' = $Surname
			'Displayname' = $NC_DisplayName
			'Samaccountname' = $NC_SAM
			'UserPrincipalName' = $NC_Email
			'AccountPassword' = (ConvertTo-SecureString -AsPlainText $Passwd -Force)
			'Enabled' = $true
			'ChangePasswordAtLogon' = $false
			'Path' = $NC_Path
			'Server' = $env:COMPUTERNAME
		}
		
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Creating new Active Directory User Account [{0}]..." -f $Properties.Name)
		New-ADUser @Properties -PassThru -ErrorAction Stop
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Active Directory User Account [{0}] successfully created." -f $Properties.Name)
		# Set additional proprties
		$secProperties = @{
			'msExchRecipientDisplayType' = "-2147483642"
			'msExchRemoteRecipientType' = "3"
			'mail' = $NC_Email
			'proxyAddresses' = "SMTP:$($NC_Email)"
			'mailNickname' = "$NC_SAM"
			'Extensionattribute15' = "$SspUid"
			'Extensionattribute14' = "$insertionprop"			
		}
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Setting additional properties for Active Directory User Account [{0}]..." -f $Properties.Name)
		Set-ADUser -Identity $nc_sam -Add $secProperties -Server $env:COMPUTERNAME -ErrorAction Stop
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Additional properties for Active Directory User Account [{0}] successfully set" -f $Properties.Name)
		
		#region Test user login
		Start-Sleep -Seconds 20
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
		$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ct, $Domain
		If ($pc.ValidateCredentials($NC_SAM, $passwd) -eq $true)
		{
			New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "Authentication successful"
			$sspresult = "Gereed|$NC_SAM is aangemaakt"
		}
		else
		{
			New-OrmLog -logvar $logvar -status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message "Authentication not successful"
			$sspresult = "Mislukt|$NC_SAM is niet volledig aangemaakt. $newadusererror"
		}
		
		#endregion Test user login
		
		#region Add to group
		$Employeefunctions = $functions -split ";"
		ForEach ($employeeFunction in $EmployeeFunctions)
		{
			Add-ADGroupMember -identity $employeeFunction -Members $nc_sam -ErrorAction Stop
			New-OrmLog -logvar $logvar -status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message "$NC_SAM added to $employeefunction"
		}
		#endregion Add to group	
	}	
	Catch
	{
		New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message ("An error occured while creating new Active Directory User Account [{0}]:[{1}]" -f $Properties.Name, ($_.Exception.Message -replace "\r\n", ". "))
		$sspresult = ('Mislukt|Fout tijdens het maken van gebruikersaccount [{0}]:[{1}]' -f $Properties.Name, ($_.Exception.Message -replace "\r\n", ". "))
		$ProcedureFailed = $true
	}	
}
#endregion Create user account

#region ssplog
$ssplog = "$Kworkingdir\$TDNumber.csv"
$ssplogvar = New-Object -TypeName PSObject -Property @{
	'logID' = ([guid]::NewGuid()).guid
	'youweID' = $TDNumber
	'sspUid' = $SspUid
	'action' = "Account aanmaken"
	'parameters' = (Get-Content -Path $KworkingDir\param.txt -Tail 1)
	'result' = $sspresult
	'companyID' = $companyid
	'last_changed' = '01-01-1700 00:00:01' # Default value in case the account was not created for some reason, in which case whenchanged value can not be determined
}

if ($ProcedureFailed -ne $true)
{
	$ssplogvar.last_changed = Get-Date (Get-ADUser -Identity $NC_SAM -Properties whenchanged | Select-Object -ExpandProperty whenchanged) -f "dd-MM-yyyy hh:mm:ss"
}

New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Creating SSP Log [{0}]...' -f $ssplog)
$ssplogvar | Export-Csv -Path $ssplog -Delimiter ";" -NoTypeInformation -ErrorAction SilentlyContinue -ErrorVariable ExportCsvError
if ($ExportCsvError)
{
	$ProcedureFailed -eq $true
	New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message ('Failed to create SSP Log [{0}]' -f $ssplog)
}
else
{
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('SSP Log [{0}] successfully created.' -f $ssplog)
}
#endregion ssplog

if ($ProcedureFailed -eq $true)
{
	New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message ('Procedure failed: [{0}]' -f $Procname)
}
else
{	
	New-OrmLog -logvar $logvar -Status 'Success' -LogDir $KworkingDir -ErrorAction Stop -Message ('Procedure completed: [{0}]' -f $Procname)
}
Stop-Transcript
#endregion Execution