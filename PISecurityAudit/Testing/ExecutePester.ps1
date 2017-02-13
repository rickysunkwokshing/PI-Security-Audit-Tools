# +-----------------------------------------------------------------------------------------------------
# | File : ExecutePester.ps1
# | Description : Script to execute unit tests with the Pester Module
# +-----------------------------------------------------------------------------------------------------

#region - Help

<#
.SYNOPSIS
Execute Pester tests.

.DESCRIPTION
Execute Pester tests.

.PARAMETER TestNameFilter
Set a test name filter.

.PARAMETER TagList
Set a list of tags corresponding to tests to execute.

.PARAMETER SkipImportTest
Don't execute import tests.

.PARAMETER SkipInvokeTest
Don't execute invoke tests.

.PARAMETER ShowTestDebuggingMessage
Show verbose message.

.EXAMPLE
.\ExecutePester.ps1

.EXAMPLE
$tl = @('RightSyntax','WrongSyntax')
.\ExecutePester.ps1 -TagList $tl

.EXAMPLE
.\ExecutePester.ps1 -ShowTestDebuggingMessage

.EXAMPLE
.\ExecutePester.ps1 -TestNameFilter 'New-OSM_PasswordOnDisk'
#>

#endregion

#region - Parameters declaration.
[CmdletBinding()]
param(
		[parameter(Mandatory = $false)]
		[String]
		$TestNameFilter = '*',

		[parameter(Mandatory = $false)]
		[String[]]
		$TagList = @(),

		[parameter(Mandatory = $false)]
		[alias('stdm')]
		[Switch]
		$ShowTestDebuggingMessage = $false)

#endregion

#region - Internal Helper Functions

	function GetScriptPath
	{
		$scriptFolder = (Get-Variable 'PSScriptRoot' -ErrorAction 'SilentlyContinue').Value
		if(!$scriptFolder)
		{
			if($MyInvocation.MyCommand.Path)
			{
				$scriptFolder = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
			}
		}
		if(!$scriptFolder)
		{
			if ($ExecutionContext.SessionState.Module.Path)
			{
				$scriptFolder = Split-Path (Split-Path $ExecutionContext.SessionState.Module.Path)
			}
		}
		if (!$scriptFolder)
		{
			$scriptFolder = $pwd
		}

		# Return path.
		return $scriptFolder
	}

#endregion

#region - Main routine

try
{
	# Define paths.
	$rootFolder = GetScriptPath
	$pesterScript = Join-Path -Path $rootFolder -ChildPath 'ImportPester.ps1'

	# Import the Pester module.
	# Documentation for Pester = https://github.com/pester/Pester/wiki
	& $pesterScript

	# Show message at console.
	if($TagList.Count -eq 0)
	{ $msg = 'Execute all tests found with *.tests.ps1 extension' }
	else
	{ $msg = 'Execute tests matching theses tags: {0} and found with *.tests.ps1 extension' -f ($TagList -Join ', ')}
	Write-Host $msg -ForegroundColor 'Yellow'

	# Set temporarily the verbose messages sent by cmdlets.
	if($ShowTestDebuggingMessage)
	{ $VerbosePreference = 'Continue' }

	# Invoke...
	# https://github.com/pester/Pester/wiki/Invoke-Pester
	Invoke-Pester -Script $($rootFolder + '\*.tests.ps1') -Tag $TagList -TestName $TestNameFilter
}
catch
{ Throw }
finally
{
	# Reset the verbose preference to it's default.
	if($ShowTestDebuggingMessage)
	{ $VerbosePreference = 'SilentlyContinue' }
}

#endregion