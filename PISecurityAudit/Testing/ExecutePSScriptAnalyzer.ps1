# Import the PSScriptAnalyzer module.
# Documentation for PSScriptAnalyzer = https://github.com/PowerShell/PSScriptAnalyzer
Import-Module 'PSScriptAnalyzer'

# Wrapper to Invoke analyzer and send results to export folder
function InvokePSScriptAnalysis ($scripts, $scriptPath, $excludedRules, $PISecAuditRoot)
{
	foreach ($script in $scripts) 
	{
		Invoke-ScriptAnalyzer -Path $($scriptPath + $script + '.psm1') -ExcludeRule $excludedRules `
							| ConvertTo-Csv | Out-File $($PISecAuditRoot + '\Export\' + $script + '.staticanalysis.csv') -Force
	}
} 

# Get the root path for the scripts to analyze.
$PISecAuditTestPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$PISecAuditRoot = Split-Path -Parent -Path $PISecAuditTestPath

# Define set of rules to exclude from the analysis, globally.
$excludedRules = @( 'PSUseShouldProcessForStateChangingFunctions' )

# Example: Scan a specific script
# Invoke-ScriptAnalyzer -Path $($PISecAuditRoot + '\Scripts\PISysAudit\' + 'PISYSAUDITCHECKLIB5' + '.psm1') -ExcludeRule $excludedRules 

# Scan all audit check modules
$libraries = @( 'PISYSAUDITCORE', 'PISYSAUDITCHECKLIB1', 'PISYSAUDITCHECKLIB2', 'PISYSAUDITCHECKLIB3', 'PISYSAUDITCHECKLIB4', 'PISYSAUDITCHECKLIB5' )
$libraryPath = $PISecAuditRoot + '\Scripts\PISysAudit\'
InvokePSScriptAnalysis $libraries $libraryPath $excludedRules $PISecAuditRoot

# Scan all utilities
$utilities = @( 'PISECCONFIGEXPORT', 'CoresightKerberosConfiguration' )
$utilityPath = $PISecAuditRoot + '\Scripts\Utilities\'
InvokePSScriptAnalysis $utilities $utilityPath $excludedRules $PISecAuditRoot
