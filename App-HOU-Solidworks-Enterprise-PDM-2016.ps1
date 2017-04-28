<#
	.Synopsis
		The Ormer template for all PowerShell Scripts.
	
	.DESCRIPTION
		The Ormer template for all PowerShell Scripts that are executed using a Kaseya Procedure.
		The template includes all requirements for scripts and logging.
	
	.PARAMETER Operator
		The Kaseya user that uses the script.
	
	.PARAMETER MachineGroup
		The Kaseya Machine Group where the Kaseya Agent running the script belongs to.
	
	.PARAMETER TDNumber
		The Topdesk incident number the Kaseya Procedure is executed for.
	
	.PARAMETER KworkingDir
		The Kaseya Agent Working Directory
	
	.EXAMPLE
		Example of how to use this script
	
	.EXAMPLE
		Another example of how to use this script
	
	.NOTES
		Author: Managed Services
		Version: 1.0
		Revisions:
		01/01/2015 - Created Template. (Managed Services)
		26/10/2015 - Changed Some Variables to Global Scope (for logging from Module Functions)
#>
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[string]$Operator,
	
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[string]$MachineGroup,
	
	[Parameter(Mandatory = $true)]
	[ValidateNotNullOrEmpty()]
	[string]$TDNumber,
	
	[Parameter(Mandatory = $true)]
	[ValidateScript({ Test-Path $_ })]
	[string]$KworkingDir,
	
	[switch]$Check,
	
	[switch]$Install
)

#region Functions
function Test-InHoudijkNetwork
{
	[CmdletBinding()]
	[OutputType([boolean])]
	param ()
	
	$NetworkAdapters = Get-WmiObject -Class 'Win32_NetworkAdapterConfiguration' -ErrorAction SilentlyContinue -ErrorVariable GetWMIObjectError
	if ($GetWMIObjectError)
	{
		Write-Output -InputObject $false
	}
	else
	{
		if ($NetworkAdapters)
		{
			$AdaptersInHoudijkNetwork = $NetworkAdapters | Where-Object -FilterScript { $_.DefaultIPGateway -match '10.101.16' -or $_.DefaultIPGateway -match '192.168.46' }
			if ($AdaptersInHoudijkNetwork -eq $null)
			{
				Write-Output -InputObject $false
			}
			else
			{
				Write-Output -InputObject $true
			}
		}
		else
		{
			Write-Output -InputObject $false
		}
	}
}
#endregion

#region StandardFramework
Import-Module -Name OrmLogging -Prefix 'Orm' -ErrorAction SilentlyContinue -ErrorVariable ImportModuleOrmLoggingError
if($ImportModuleOrmLoggingError)
{
    Write-Error "Unable to import the Ormer Logging Powershell Module"
    Write-Error "$($ImportModuleOrmLoggingError[0].Exception.Message)"
    Throw
}
Import-Module -Name OrmToolkit -Prefix 'Orm' -ErrorAction SilentlyContinue -ErrorVariable ImportModuleOrmToolkitError
if($ImportModuleOrmToolkitError)
{
    Write-Error "Unable to import the Ormer Toolkit Powershell Module"
    Write-Error "$($ImportModuleOrmToolkitError[0].Exception.Message)"
    Throw
}

Set-Location $KworkingDir -ErrorAction SilentlyContinue -ErrorVariable SetLocationError
if($SetLocationError)
{
    Write-Error "Unable to set the working directory of the script"
    Write-Error "$($SetLocationError[0].Exception.Message)"
    Throw
}

$Global:KworkingDir = $KworkingDir
$Domain = $env:USERDOMAIN
$MachineName = $env:COMPUTERNAME
$Procname = ($MyInvocation.MyCommand.Name).Substring(0,(($MyInvocation.MyCommand.Name).Length)-4)
$Customer = $MachineGroup.Split('.')[2]

$Global:logvar = New-Object -TypeName PSObject -Property @{
    'Domain' = $Domain 
    'MachineName' = $MachineName
    'Procname' = $Procname
    'Customer' = $Customer
    'Operator'= $Operator
    'TDNumber'= $TDNumber
}
#endregion StandardFramework
    
#region Execution

#region Get Operating System Information
New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message 'Retrieving information about the Operating System...'
$OSDetails = Get-OrmOSInformation -ErrorAction SilentlyContinue -ErrorVariable GetOSInformationError
if ($GetOSInformationError)
{
	Set-OrmErrorVariableAction -Variable $GetOSInformationError -Action 'Stop'
}
else
{
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message 'Operating System Information:'
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Name: {0}" -f $OSDetails.Name)
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Type: {0}" -f $OSDetails.Type)
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Architecture: {0}" -f $OSDetails.Architecture)
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ("Full Version: {0}" -f $OSDetails.FullVersion)
}
#endregion

#region Script variables

# define check variables
$ApplicationPrerequisiteRegKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Ormer\Uninstall'
$ApplicationPrerequisiteRegValue = 'SolidworksEPDM2013Uninstalled'
$ApplicationPrerequisite2RegKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Ormer\Applications\Solidworks'
$ApplicationPrerequisite2RegValue = 'Installed'
$ApplicationInstallationRegKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Ormer\Applications\Solidworks'
$ApplicationInstallationRegValue = 'EPDM2016Installed'
$ApplicationInstallationRegValueData = 'True'
$ApplicationCheckFile = 'Application.Installed'

# define Application Name
$ApplicationToInstall = 'Solidworks Enterprise PDM 2016 SP5'

#define Client Install Folder
$ClientSetupRoot = ('{0}\Solidworks\SolidWorks2016SP5PDMOnly' -f $KworkingDir)

#define Client Install Directory
if ($OSDetails.Architecture -eq 'x64')
{
	$InstallDir= ${env:ProgramFiles(x86)}	
}
else
{
	$InstallDir = $env:ProgramFiles
}

#define Required Installation Files
$RequiredInstallationFiles = @{
	'SETUP' = ('{0}\startswinstall.exe' -f $ClientSetupRoot)
	'SETUPXML' = ('{0}\64bit\AdminDirector.xml' -f $ClientSetupRoot)
}

#define Required Installation Files which depend on Operating System version
if ($OSDetails.Architecture -eq 'x64')
{
	
}
else
{
	
}
#endregion

#region Check if application is currently installed
if ($Check)
{
	Remove-Item "$KworkingDir\ProcedureLog.log" -Force -ErrorAction SilentlyContinue
	New-OrmLog -logvar $logvar -Status 'Start' -LogDir $KworkingDir -ErrorAction Stop -Message ('Starting procedure: [{0}]' -f $Procname)
	
	<#
	Install Procedure of Solidworks Enterprise PDM 2016 should only be started, if the following prerequisites have been met:
	RegValue HKEY_LOCAL_MACHINE\SOFTWARE\Ormer\Uninstall --> SolidworksEPDM2013Uninstalled exists
	AND
	RegValue HKEY_LOCAL_MACHINE\SOFTWARE\Ormer\Applications\Solidworks --> Installed equals 'False'
	AND
	RegValue HKEY_LOCAL_MACHINE\SOFTWARE\Ormer\Applications\Solidworks --> EPDM2016Installed does not exist
	#>
	
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Checking if computer is currently located in the Houdijk network...')
	if ((Test-InHoudijkNetwork) -eq $true)
	{
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Computer is currently located in the Houdijk network.')
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Checking if prequisites are met for Installation Procedure of [{0}]...' -f $ApplicationToInstall)
		$PrereqCheck = (Get-ItemProperty -Path Registry::$($ApplicationPrerequisiteRegKey) -Name $ApplicationPrerequisiteRegValue -ErrorAction SilentlyContinue -ErrorVariable GetRegistryItem).$ApplicationPrerequisiteRegValue
		$PrereqCheck2 = (Get-ItemProperty -Path Registry::$($ApplicationPrerequisite2RegKey) -Name $ApplicationPrerequisite2RegValue -ErrorAction SilentlyContinue -ErrorVariable GetRegistryItem).$ApplicationPrerequisite2RegValue
		
		if ($PrereqCheck -eq $null)
		{
			New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Prequisites for Installation Procedure of [{0}] are not met. Installation Procedure will not be performed.' -f $ApplicationToInstall)
			Write-OrmCheckResult -FileName $ApplicationCheckFile -Value $true
			New-OrmLog -logvar $logvar -Status 'Success' -LogDir $KworkingDir -ErrorAction Stop -Message ('Procedure completed: [{0}]' -f $procname)
		}
		else
		{
			if ($PrereqCheck2 -eq $null)
			{
				New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Prequisites for Installation Procedure of [{0}] are not met. Installation Procedure will not be performed.' -f $ApplicationToInstall)
				Write-OrmCheckResult -FileName $ApplicationCheckFile -Value $true
				New-OrmLog -logvar $logvar -Status 'Success' -LogDir $KworkingDir -ErrorAction Stop -Message ('Procedure completed: [{0}]' -f $procname)
			}
			else
			{
				switch ($PrereqCheck2)
				{
					'True' {
						New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Prequisites for Installation Procedure of [{0}] are not met. Installation Procedure will not be performed.' -f $ApplicationToInstall)
						Write-OrmCheckResult -FileName $ApplicationCheckFile -Value $true
						New-OrmLog -logvar $logvar -Status 'Success' -LogDir $KworkingDir -ErrorAction Stop -Message ('Procedure completed: [{0}]' -f $procname)
					}
					'False' {
						New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Prequisites for Installation Procedure of [{0}] are met.' -f $ApplicationToInstall)
						New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Checking if Installation Procedure of [{0}] has been completed before...' -f $ApplicationToInstall)
						$InstallCheck = (Get-ItemProperty -Path Registry::$($ApplicationInstallationRegKey) -Name $ApplicationInstallationRegValue -ErrorAction SilentlyContinue -ErrorVariable GetRegistryItem).$ApplicationInstallationRegValue
						
						if ($InstallCheck -eq $null)
						{
							New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Installation procedure has NOT been completed before. Initiating Installation procedure...')
							Write-OrmCheckResult -FileName $ApplicationCheckFile -Value $false
						}
						else
						{
							New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Installation procedure has been completed before. Installation Procedure will not be executed.')
							Write-OrmCheckResult -FileName $ApplicationCheckFile -Value $true
							New-OrmLog -logvar $logvar -Status 'Success' -LogDir $KworkingDir -ErrorAction Stop -Message ('Procedure completed: [{0}]' -f $procname)
						}
					}
					default
					{
						New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message ('Value [{0}] is invalid for Prequisites Check. Unable to determine if Prerequisites are met.' -f $PrereqCheck2)
						Write-OrmCheckResult -FileName $ApplicationCheckFile -Value $true
						New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message ('Procedure failed: [{0}]' -f $procname)
					}
				}
			}
		}
	}
	else
	{
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Computer is currently NOT located in the Houdijk network. Installation Procedure will not be executed.')
		Write-OrmCheckResult -FileName $ApplicationCheckFile -Value $true
	}
}
#endregion

#region Install application
if ($Install)
{	
	#region Check if all required installation files are available
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message 'Checking if all required installation files exist...'
	foreach ($RequiredInstallationFile in $RequiredInstallationFiles.Keys)
	{
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Checking if installation file [{0}] exists...' -f $RequiredInstallationFiles.Item($RequiredInstallationFile))
		if ((Test-Path -Path $RequiredInstallationFiles.Item($RequiredInstallationFile)) -eq $true)
		{
			New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Installation file [{0}] exists' -f $RequiredInstallationFiles.Item($RequiredInstallationFile))
		}
		else
		{
			New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message ('Installation file [{0}] does not exists' -f $RequiredInstallationFiles.Item($RequiredInstallationFile))
			New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message "Procedure failed: $($procname)"
			Throw
		}
	}
	#endregion	
	
	#region Install Application and related applications
	
	#region Install Solidworks Enterprise PDM 2016 SP5
	$ApplicationInstaller = $RequiredInstallationFiles.SETUP
	$ApplicationInstallParameters = '/install /now'
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Installing [{0}]...' -f $ApplicationToInstall)
	New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Starting setup [{0}] with arguments [{1}]' -f $ApplicationInstaller, $ApplicationInstallParameters)
	$Process = Start-Process -FilePath $ApplicationInstaller -ArgumentList $ApplicationInstallParameters -PassThru -ErrorAction SilentlyContinue -ErrorVariable StartProcessError
	$Handle = $Process.Handle
	if (-not ($StartProcessError))
	{
		Do
		{
			Start-Sleep -Seconds 1
		}
		While ($Process.HasExited -eq $false)
		
		New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Installation finished with exit code: [{0}]' -f $Process.ExitCode)
		if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010)
		{
			New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Successfully installed [{0}]' -f $ApplicationToInstall)
			
			# Write Success Registry Value
			New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Updating Registry indicating Application [{0}] was successfully installed' -f $ApplicationToInstall)
			if ((Test-Path -Path Registry::$($ApplicationInstallationRegKey)) -eq $false)
			{
				New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Creating Registry Key [{0}]...' -f $ApplicationInstallationRegKey)
				New-Item -Path Registry::$($ApplicationInstallationRegKey) -Force -ErrorAction SilentlyContinue -ErrorVariable NewItemError | Out-Null
				if ($NewItemError)
				{
					Set-OrmErrorVariableAction -Variable $NewItemError -Action 'Stop'
				}
				else
				{
					New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Registry Key [{0}] was successfully created.' -f $ApplicationInstallationRegKey)
				}
			}
			
			New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Writing Registry Value [{0}] with Value Data [{1}] in Registry Key [{2}]...' -f $ApplicationInstallationRegValue, $ApplicationInstallationRegValueData, $ApplicationInstallationRegKey)
			Set-ItemProperty -Path Registry::$($ApplicationInstallationRegKey) -Name $ApplicationInstallationRegValue -Value $ApplicationInstallationRegValueData -Force -ErrorAction SilentlyContinue -ErrorVariable SetItemPropertyError
			if ($SetItemPropertyError)
			{
				Set-OrmErrorVariableAction -Variable $SetItemPropertyError -Action 'Stop'
			}
			else
			{
				New-OrmLog -logvar $logvar -Status 'Info' -LogDir $KworkingDir -ErrorAction Stop -Message ('Registry Value [{0}] with Value Data [{1}] in Registry Key [{2}] was successfully set.' -f $ApplicationInstallationRegValue, $ApplicationInstallationRegValueData, $ApplicationInstallationRegKey)
			}
		}
		else
		{
			New-OrmLog -logvar $logvar -Status 'Error' -LogDir $KworkingDir -ErrorAction Stop -Message 'Installation Exit Code indicates failure.'
			New-OrmLog -logvar $logvar -Status 'Failure' -LogDir $KworkingDir -ErrorAction Stop -Message ('Procedure failed: [{0}]' -f $Procname)
			Throw
		}
	}
	else
	{
		Set-OrmErrorVariableAction -Variable $StartProcessError -Action 'Stop'
	}
	#endregion		
	
	#endregion	
	
	# Remove the temporary directory
	Remove-Item -Path $ClientSetupRoot -Recurse -Force -ErrorAction SilentlyContinue
	
	New-OrmLog -logvar $logvar -Status 'Success' -LogDir $KworkingDir -ErrorAction Stop -Message "Procedure completed: $($procname)"
}
#endregion Execution

#endregion