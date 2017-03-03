# +-----------------------------------------------------------------------------------------------------
# | File : ImportPester.ps1
# | Description : Script to properly import Pester.
# +-----------------------------------------------------------------------------------------------------

#region - Main routine

try
{
	# Get module.
	$modulesObj = Get-Module | Where-Object { $_.Name -match '^pester$' }

	# Set flags.
	$notLoaded = ($modulesObj.Count -eq 0)
	$hasManyVersion = ($modulesObj.Count -gt 1)

	if($hasManyVersion)
	{
		$msg = "Many instances of 'Pester' have been detected"
		Throw $msg
	}
	elseif($notLoaded)
	{ Import-Module 'Pester' -Force }

}
catch
{ Throw }

#endregion