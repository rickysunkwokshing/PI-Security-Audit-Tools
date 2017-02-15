# +-----------------------------------------------------------------------------------------------------
# | File : PISysAuditCORE.tests.ps1
# | Description : Script to unit test functions in the core module.
# +-----------------------------------------------------------------------------------------------------

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

try
{
	# Define paths.
	$rootFolder = GetScriptPath
	$pesterScript = Join-Path -Path $rootFolder -ChildPath 'ImportPester.ps1'
	$PISysAuditScript = Join-Path -Path $(Split-Path -Path $rootFolder) -ChildPath '\Scripts\PISYSAUDIT\PISYSAUDITCORE.psm1'

	# Import the Pester module.
	# Documentation for Pester = https://github.com/pester/Pester/wiki
	& $pesterScript

	Import-Module $PISysAuditScript

	#	Set debug level.
	$DBGLevel = 2

	#region - Public Functions
	
	
	#endregion
	
	#region - Private Functions

	Describe -Tags @('Internal', 'Validation') 'PathConcat' {
		
		$testCases = @(
							@{ ParentPath = 'C:\'; ChildPath = 'Child' },
							@{ ParentPath = 'C:\Parent'; ChildPath = 'Child' },
							@{ ParentPath = 'C:\Parent\'; ChildPath = 'Child' },
							@{ ParentPath = 'C:\Parent\'; ChildPath = '\Child' },
							@{ ParentPath = 'Z:\Parent\'; ChildPath = '\Child\' },
							@{ ParentPath = '\\Parent\'; ChildPath = '\Child\' }
						)

		It 'combines a parent path to a child' -TestCases $testCases {
			param($ParentPath, $ChildPath)

			$resultObj = PathConcat -ParentPath $ParentPath -ChildPath $ChildPath  
			$resultObj | Should Match '^([a-zA-Z]:|\\)(\\Parent)?\\Child[\\]?'
		}
	}

	#endregion
}
catch
{ Throw }