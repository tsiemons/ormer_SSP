<#
	Script to Insert the Kaseya Procedure Log into the Logging Database
#>
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[ValidateScript({ Test-Path $_ })]
	[ValidateNotNullOrEmpty()]
	[string]$LogFilePath = 'C:\kworking\ProcedureLog.log',
	
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[string]$ServerInstance = 'tcp:orme-azsql-01.database.windows.net',
	
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[int]$ServerPort = 1433,
	
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[string]$Database = 'ORME-KaseyaLogging',
	
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[string]$UserName = 'ORME-MS@orme-azsql-01',
	
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[string]$Password = 'GY5H+6N9G4EJ3wf*#xLa',
	
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[int]$QueryTimeout = 600,
	
	[Parameter(Mandatory = $false)]
	[ValidateNotNullOrEmpty()]
	[int]$ConnectionTimeout = 30
)

#region Functions
function Format-LogEntry
{
<#
	.SYNOPSIS
		Formats a LogEntry so it can be added to the Logging Database
	
	.DESCRIPTION
		Formats a LogEntry so it can be added to the Logging Database
	
	.PARAMETER LogEntry
		Expects a LogEntry in the following Format:
		[Date][Time][Operator][Domain][Machinename][Customer][TDNumber][Procname][Status][Message]
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$LogEntry
	)
	
	# Split the LogEntry on ][
	$LogEntryArray = $LogEntry -split '\]\['
	
	# Create an array that will hold the formatted LogEntry
	[array]$FormattedLogEntryArray = @()
	
	# The First field of the $LogEntryArray should start with [ after the split. Remove the [.
	if ($LogEntryArray[0].StartsWith('['))
	{
		$FormattedLogEntryArray += $LogEntryArray[0].Substring(1)
	}
	
	# The Last field of the $LogEntryArray should end with ] after the split. Remove the ].
	if ($LogEntryArray[($LogEntryArray.Length) - 1].EndsWith(']'))
	{
		$LogEntryArray[($LogEntryArray.Length) - 1] = $LogEntryArray[($LogEntryArray.Length) - 1].Substring(0, (($LogEntryArray[($LogEntryArray.Length) - 1]).Length) - 1)
	}
	
	# Add the [Date][Time][Operator][Domain][Machinename][Customer][TDNumber][Procname][Status] fields to the formatted LogEntry
	for ($i = 1; $i -lt 9; $i++)
	{
		$FormattedLogEntryArray += $LogEntryArray[$i]
	}
	
	# The Message field starts at the 10th position (9th index) of the $LogEntryArray, start the formatted message with this index
	$NewMessage = $LogEntryArray[$i]
	
	#The Line was split on ][, so add ][ to the rest of the entries in the array to recreate the original Message
	for ($i = 10; $i -lt $LogEntryArray.Length; $i++)
	{
		$NewMessage = "$($NewMessage)][$($LogEntryArray[$i])"
	}
	
	# Add the Regenerated Message to the $FormattedLogEntryArray
	$FormattedLogEntryArray += $NewMessage
	
	# Escape the single quote character in all logging fields, so it can be inserted into a SQL DB
	for ($i = 0; $i -lt $FormattedLogEntryArray.Length; $i++)
	{
		$FormattedLogEntryArray[$i] = $FormattedLogEntryArray[$i].Replace("`'", "`'`'")
	}
	
	# Write the $FormattedLogEntryArray to the pipeline
	Write-Output -InputObject $FormattedLogEntryArray
}

function Test-GUID
{
<#
	.SYNOPSIS
		Tests if the value specified by the -GUID parameter is a valid GUID.
	
	.DESCRIPTION
		Tests if the value specified by the -GUID parameter is a valid GUID.
	
	.PARAMETER GUID
		A description of the GUID parameter.
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param
	(
		[ValidateNotNullOrEmpty()]
		[string]$GUID
	)
	
	if ($GUID -match '(\{|\()?[A-Za-z0-9]{4}([A-Za-z0-9]{4}\-?){4}[A-Za-z0-9]{12}(\}|\()?')
	{
		Write-Output -InputObject $true
	}
	else
	{
		Write-Output -InputObject $false
	}
}

#endregion

# Create the SQL ConnectionString
$Connectionstring = "Server = $($ServerInstance),$($ServerPort); Database = $Database; User ID = $username;Password= $Password; Integrated Security = False; Encrypt = True; Trusted_Connection = False; Connection Timeout = $($ConnectionTimeout.ToString())"

# Set the Table in which the Logging will be written
$Table = 'Logging'

Try
{
	# Open database
	Write-Verbose -Message 'Connecting to SQL Server...'
	Write-Verbose -Message "Connection String: $($Connectionstring)"
	Write-Verbose -Message "Connection Timeout: $($ConnectionTimeout.ToString()) seconds"
	
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlConnection.ConnectionString = $Connectionstring
	$Sqlconnection.Open()
	Write-Verbose -Message 'Connected to SQL Server!'
}
Catch
{
	Throw $_
}

# Read the contents of the ProcedureLog
Write-Verbose -Message "Reading the contents of $($LogFilePath)"
$LogFile = Get-Content -Path $LogFilePath

# Generate a GUID
$GUID = [Guid]::NewGuid()

# Process all Lines of the ProcedureLog
for ($i = 0; $i -lt $LogFile.Length; $i++)
{
	# Check if the Line is not an empty string or $null
	if (-not ($LogFile[$i].Trim() -eq '' -or $LogFile[$i] -eq $null))
	{
		# Format the Log Entry, so it can be inserted into the Logging DB
		$LogEntry = Format-LogEntry -LogEntry $LogFile[$i]
		
		# Check if the TDNumber field contains a GUID, which means the Procedure was started by the Self Service Portal
		if ((Test-GUID -GUID $LogEntry[6]) -eq $true)
		{
			# Set the LogGUID to the GUID specified in the TDNumber field
			$LogGUID = $LogEntry[6]
		}
		else
		{
			# Set the LogGUID to the generated GUID
			$LogGUID = $GUID
		}
		
		$TableRecord = New-Object -TypeName PSObject -Property @{
			'LogGUID' = $LogGUID
			'LogLineID' = $i + 1
			'DateTime' = $LogEntry[0].Replace('-', '/') + ' ' + $LogEntry[1]
			'Time' = $LogEntry[1]
			'Operator' = $LogEntry[2]
			'Domain' = $LogEntry[3]
			'MachineName' = $LogEntry[4]
			'Customer' = $LogEntry[5]
			'TDNumber' = $LogEntry[6]
			'Procname' = $LogEntry[7]
			'Status' = $LogEntry[8]
			'Message' = $LogEntry[9]
		}
		
		$Query = "insert into $($Table) 
                  (LogGUID,LogLIneID,DateTime,Operator,Domain,MachineName,Customer,TDNumber,Procname,Status,Message) 
                  values ('$($TableRecord.LogGUID)',
						  '$($TableRecord.LogLineID)',
						   Convert(datetime2,`'$($TableRecord.DateTime)`',103),                          
                          '$($TableRecord.Operator)',
                          '$($TableRecord.Domain)',
                          '$($TableRecord.MachineName)',
                          '$($TableRecord.Customer)',
                          '$($TableRecord.TDNumber)',
                          '$($TableRecord.Procname)',
                          '$($TableRecord.Status)',  
                          '$($TableRecord.Message)'
                         )"
		Try
		{
			# Write Record to database
			Write-Verbose -Message 'Executing Query:'
			Write-Verbose -Message "$($Query)"
			$Cmd = New-Object system.Data.SqlClient.SqlCommand($Query, $SqlConnection)
			$Cmd.CommandTimeout = $QueryTimeout
			$DataSet = New-Object system.Data.DataSet
			$DataAdapter = New-Object system.Data.SqlClient.SqlDataAdapter($Cmd)
			[void]$DataAdapter.fill($DataSet)
			$DataSet.Tables[0]
			Write-verbose -Message 'Record added'
		}
		Catch
		{
			Throw $_
		}
	}
}

# Close Database Connection
Try
{
	Write-Verbose -Message 'Closing SQL Connection...'
	$Sqlconnection.Close()
	Write-Verbose -Message 'Connection Closed!'
}
Catch
{
	Throw $_
}