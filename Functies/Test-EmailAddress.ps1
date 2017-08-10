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