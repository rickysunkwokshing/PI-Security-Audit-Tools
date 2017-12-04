# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB6.psm1
# * Description:  Validation rules for PI Web API.
# *
# * Copyright 2016 OSIsoft, LLC
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# * 
# *   <http://www.apache.org/licenses/LICENSE-2.0>
# * 
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *
# * Modifications copyright (C) 2016 Harry Paul, OSIsoft, LLC
# * Created validation rule module based off of template used for the
# * previous modules.
# *
# ************************************************************************
# Version History:
# ------------------------------------------------------------------------
#
# ************************************************************************

# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

# ........................................................................
# Public Functions
# ........................................................................
function Get-PISysAudit_FunctionsFromLibrary6
{
<#  
.SYNOPSIS
Get functions from PI Web API library at or below the specified level.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[int]
		$AuditLevelInt = 1)

	# Form a list of all functions that need to be called to test
	# the machine compliance.
	$listOfFunctions = @()
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIWebAPIVersion"  1 "AU60001"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIWebApiCSRF"     1 "AU60002"

	# Return all items at or below the specified AuditLevelInt
	return $listOfFunctions | Where-Object Level -LE $AuditLevelInt
}

function Get-PISysAudit_GlobalPIWebApiConfiguration
{
<#  
.SYNOPSIS
Gathers global data for all PI Web API checks.
.DESCRIPTION
Several checks reuse information.  This command puts the configuration information
in a global object to reduce the number of remote calls, improving performance and 
simplifying validation logic.

Information included in global configuration:
	Version            - application version
	AFServer           - configuration AF Server
	AFElement          - configuration AF Element

#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{
	$fn = GetFunctionName

	# Reset global config object.
	$global:PIWebApiConfiguration = $null
	
	$scriptBlock = {
			$pisystemKey = "HKLM:\Software\PISystem\"

			# Registry keys
			$PIWebApiVersion = Get-ItemProperty -Path $($pisystemKey + "WebAPI") -Name "Version" | Select-Object -ExpandProperty "Version"
			$PIWebApiDirectory = Get-ItemProperty -Path $($pisystemKey + "WebAPI") -Name "InstallationDirectory" | Select-Object -ExpandProperty "InstallationDirectory"

			# PI Web API Configuration
			$InstallationConfig = Get-Content -Path $(Join-Path $PIWebApiDirectory "InstallationConfig.json")
			$afMatch = $InstallationConfig | Select-String -Pattern 'ConfigAssetServer\": \"(.*)\"'
			if($afMatch) { $PIWebApiAF = $afMatch.Matches.Groups[1].Value }
			$elemMatch = $InstallationConfig | Select-String -Pattern 'ConfigInstance\": \"(.*)\"'
			if($elemMatch) { $PIWebApiElement = $elemMatch.Matches.Groups[1].Value }

			# Construct a custom object to store the config information
			$Configuration = New-Object PSCustomObject
			$Configuration | Add-Member -MemberType NoteProperty -Name Version -Value $PIWebApiVersion
			$Configuration | Add-Member -MemberType NoteProperty -Name AFServer -Value $PIWebApiAF
			$Configuration | Add-Member -MemberType NoteProperty -Name AFElement -Value $PIWebApiElement
			
			return $Configuration
		}
	try
	{
		if($LocalComputer)
		{ $global:PIWebApiConfiguration = & $scriptBlock }
		else
		{ $global:PIWebApiConfiguration = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the retrieval of the Global PI Web API configuration."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
}
END {}	

}


function Get-PISysAudit_CheckPIWebApiVersion
{
<#  
.SYNOPSIS
AU60001 - PI Web API Version
.DESCRIPTION
VALIDATION: Verifies PI Web API version.<br/>
COMPLIANCE: Upgrade to the latest version of PI Web API. See the PI 
Web API product page for the latest version and associated documentation:<br/>
<a href="https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/">https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/ </a><br/>
For more information on the upgrade procedure, see "PI Web API Installation" 
in the PI Live Library.<br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/web-api-v8/GUID-1B8C5B9F-0CD5-4B98-9283-0F5801AB850B">https://livelibrary.osisoft.com/LiveLibrary/content/en/web-api-v8/GUID-1B8C5B9F-0CD5-4B98-9283-0F5801AB850B</a><br/>
Associated security bulletins:<br/>
<a href="https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/Alerts">https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/Alerts</a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{		
		$installVersion = $global:PIWebApiConfiguration.Version	
		
		$installVersionTokens = $installVersion.Split(".")
		# Form an integer value with all the version tokens.
		[string]$temp = $InstallVersionTokens[0] + $installVersionTokens[1] + $installVersionTokens[2] + $installVersionTokens[3]
		$installVersionInt64 = [int64]$temp
		if($installVersionInt64 -ge 190000)
		{
			$result = $true
			$msg = "Version $installVersion is compliant."
		}	
		else 
		{
			$result = $false
			$msg = "Noncompliant version ($installVersion) detected. Upgrading to the latest PI Web API version is recommended. "
			$msg += "See https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/ for the latest version and associated documentation."
		}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU60001" `
									-ain "PI Web API Version" -aiv $result `
									-aif $fn -msg $msg `
									-Group1 "PI System" -Group2 "PI Web API" `
									-Severity "Medium"																																																
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPIWebApiCSRF
{
<#
.SYNOPSIS
AU60002 - PI Web API CSRF
.DESCRIPTION
VALIDATION: Checks for enabled CSRF Defense in the PI Web API.<br/>
COMPLIANCE: Verify that Cross-Site Request Forgery defense is enabled. 
This is configured by setting "EnableCSRFDefense" to True on the 
PI Web API configuration element. for more information, see AL00316.<br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/Alerts/AL00316">https://techsupport.osisoft.com/Troubleshooting/Alerts/AL00316</a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{
		# CSRF Defense only available in 1.9 and later
		$installVersion = $global:PIWebApiConfiguration.Version
		$installVersionInt64 = [int64]($installVersion.Split('.') -join '')

		if($installVersionInt64 -ge 190000)
		{
			# Attempt connection to configuration AF Server
			$configAF = Get-AFServer $global:PIWebApiConfiguration.AFServer
			if($configAF)
			{
				$configAF = Connect-AFServer -AFServer $configAF

				# Drill into Configuration DB to get Web API config element
				$configDB = Get-AFDatabase -AFServer $configAF -Name 'Configuration'
				$osisoft = Get-AFElement -AFDatabase $configDB -Name 'OSIsoft'
				$webAPI = Get-AFElement -AFElement $osisoft -Name 'PI Web API'
				$configElem = Get-AFElement -AFElement $webAPI -Name $global:PIWebApiConfiguration.AFElement
				$systemConfig = Get-AFElement -AFElement $configElem -Name 'System Configuration'
				$CsrfDefense = Get-AFAttribute -AFElement $systemConfig -Name 'EnableCSRFDefense'

				if($null -ne $CsrfDefense)
				{
					$CsrfEnabled = $CsrfDefense.GetValue()
					if($CsrfEnabled.Value -eq $true)
					{
						$result = $true
						$msg = "CSRF Defense is enabled on the PI Web API."
					}
					else
					{
						$result = $false
						$msg = "CSRF Defense is disabled on the PI Web API."
					}
				}
				else
				{
					$result = $false
					$msg = "Unable to locate EnableCSRFDefense setting for the PI Web API."
				}
			}
			else
			{
				$result = "N/A"
				$msg = "Unable to connect to PI Web API configuration AF Server '$($global:PIWebApiConfiguration.AFServer)'"
				Write-PISysAudit_LogMessage $msg "Error" $fn
			}
		}
		else
		{
			$result = $false
			$msg = "CSRF Defense only available in PI Web API 2017 or later."
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
		$result = "N/A"
	}

	# Define the results in the audit table
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU60002" `
									-ain "PI Web API CSRF" -aiv $result `
									-aif $fn -msg $msg `
									-Group1 "PI System" -Group2 "PI Web API" `
									-Severity "Medium"
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Add your cmdlet after this section. Don't forget to add an intruction
# to export them at the bottom of this script.
# ........................................................................
function Get-PISysAudit_TemplateAU6xxxx
{
<#  
.SYNOPSIS
AU6xxxx - <Name>
.DESCRIPTION
VALIDATION: <Enter what the verification checks>
COMPLIANCE: <Enter what it needs to be compliant>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{		
		# Enter routine.
		# Use information from $global:PIVisionConfiguration whenever possible to 
		# focus on validation simplify logic. 		
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU6xxxx" `
									-ain "<Name>" -aiv $result `
									-aif $fn -msg $msg `
									-Group1 "<Category 1>" -Group2 "<Category 2>" `
									-Group3 "<Category 3>" -Group4 "<Category 4>" `
									-Severity "<Severity>"																																																
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Export Module Member
# ........................................................................
# <Do not remove>
Export-ModuleMember Get-PISysAudit_GlobalPIWebApiConfiguration
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary6
Export-ModuleMember Get-PISysAudit_CheckPIWebApiVersion
Export-ModuleMember Get-PISysAudit_CheckPIWebApiCSRF
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU6xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU1xxxx