# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB5.psm1
# * Description:  Validation rules for PI Coresight.
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

function NewAuditFunction
{
    Param($name, $level)
    $obj = New-Object pscustomobject
    $obj | Add-Member -MemberType NoteProperty -Name 'Name' -Value $name
    $obj | Add-Member -MemberType NoteProperty -Name 'Level' -Value $level
    return $obj
}

# ........................................................................
# Public Functions
# ........................................................................
function Get-PISysAudit_FunctionsFromLibrary5
{
<#  
.SYNOPSIS
Get functions from Coresight library at or below the specified level.
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
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckCoresightVersion"  1 # AU50001
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckCoresightAppPools" 1 # AU50002
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CoresightSSLcheck"      1 # AU50003
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CoresightSPNcheck"      1 # AU50004
	
	# Return all items at or below the specified AuditLevelInt
	return $listOfFunctions | Where-Object Level -LE $AuditLevelInt
}

function Get-PISysAudit_GlobalPICoresightConfiguration
{
<#  
.SYNOPSIS
Gathers global data for all Coresight checks.
.DESCRIPTION
Several checks reuse information.  This command puts the configuration information
in a global object to reduce the number of remote calls, improving performance and 
simplifying validation logic.

Information included in global configuration:
	Version            - application version
	Hostname           - web server hostname
	MachineDomain      - web server machine domain
	WebSite            - IIS site hosting application
	Bindings           - bindings on hosting site
	ServiceAppPoolType - type of user running the service app app pool
	AdminAppPoolType   - type of user running the admin app app pool
	ServiceAppPoolUser - user running the service app app pool
	AdminAppPoolUser   - user running the admin app app pool
	BasicAuthEnabled   - boolean indicating if site is using basic
	UsingHTTPS         - boolean indicating if site is using https
	sslFlagsSite       - SSL setting at the site level
	sslFlagsApp        - SSL setting at the site app

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
	$global:CoresightConfiguration = $null
	
	$scriptBlock = {
			$ProductName = 'Coresight'
			Import-Module WebAdministration
			
			# Registry keys
			$Version = Get-ItemProperty -Path "HKLM:\Software\PISystem\Coresight" -Name "CurrentVersion" | Select-Object -ExpandProperty "CurrentVersion"
			$MachineDomain = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" -Name "Domain" | Select-Object -ExpandProperty "Domain"
			$Hostname = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" | Select-Object -ExpandProperty "ComputerName"
			$Site = Get-ItemProperty -Path $("HKLM:\Software\PISystem\" + $ProductName) -Name "WebSite" | Select-Object -ExpandProperty "WebSite"
			
			# IIS Configuration
			$Bindings = Get-WebBinding -Name $Site
			$UsingHTTPS = $Bindings.protocol -contains "https"
			$sslFlagsSite = Get-WebConfigurationProperty -Location $($Site.ToString()) -Filter system.webServer/security/access -Name "sslFlags"
			$sslFlagsApp = Get-WebConfigurationProperty -Location $($Site.ToString() + '/Coresight') -Filter system.webServer/security/access -Name "sslFlags"
			$BasicAuthEnabled = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/BasicAuthentication -Name Enabled -location $($Site + '/Coresight') | select-object Value	
			
			# App Pool Info 
			$ServiceAppPoolType = Get-ItemProperty $('iis:\apppools\' + $ProductName + 'serviceapppool') -Name processmodel.identitytype
			$AdminAppPoolType = Get-ItemProperty $('iis:\apppools\' + $ProductName + 'adminapppool') -Name processmodel.identitytype
			$ServiceAppPoolUser = Get-ItemProperty $('iis:\apppools\' + $ProductName + 'serviceapppool') -Name processmodel.username.value
			$AdminAppPoolUser = Get-ItemProperty $('iis:\apppools\' + $ProductName + 'adminapppool') -Name processmodel.username.value
			
			# Construct a custom object to store the config information
			$Configuration = New-Object PSCustomObject
			$Configuration | Add-Member -MemberType NoteProperty -Name Version -Value $Version
			$Configuration | Add-Member -MemberType NoteProperty -Name Hostname -Value $Hostname
			$Configuration | Add-Member -MemberType NoteProperty -Name MachineDomain -Value $MachineDomain
			$Configuration | Add-Member -MemberType NoteProperty -Name WebSite -Value $Site
			$Configuration | Add-Member -MemberType NoteProperty -Name Bindings -Value $Bindings
			$Configuration | Add-Member -MemberType NoteProperty -Name ServiceAppPoolType -Value $ServiceAppPoolType
			$Configuration | Add-Member -MemberType NoteProperty -Name AdminAppPoolType -Value $AdminAppPoolType
			$Configuration | Add-Member -MemberType NoteProperty -Name ServiceAppPoolUser -Value $ServiceAppPoolUser
			$Configuration | Add-Member -MemberType NoteProperty -Name AdminAppPoolUser -Value $AdminAppPoolUser
			$Configuration | Add-Member -MemberType NoteProperty -Name BasicAuthEnabled -Value $BasicAuthEnabled
			$Configuration | Add-Member -MemberType NoteProperty -Name UsingHTTPS -Value $UsingHTTPS
			$Configuration | Add-Member -MemberType NoteProperty -Name sslFlagsSite -Value $sslFlagsSite
			$Configuration | Add-Member -MemberType NoteProperty -Name sslFlagsApp -Value $sslFlagsApp
			
			return $Configuration
		}
	try
	{
		if($LocalComputer)
		{ $global:CoresightConfiguration = & $scriptBlock }
		else
		{ $global:CoresightConfiguration = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock }
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the retrieval of the Global Coresight configuration."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
}
END {}	

}

function Get-PISysAudit_CheckCoresightVersion
{
<#  
.SYNOPSIS
AU50001 - Check for latest version of Coresight
.DESCRIPTION
VALIDATION: verifies PI Coresight version.<br/>
COMPLIANCE: upgrade to the latest version of PI Coresight.  For more information, 
see "Upgrade a PI Coresight installation" in the PI Live Library.<br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-5CF8A863-E056-4B34-BB6B-8D4F039D8DA6">https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-5CF8A863-E056-4B34-BB6B-8D4F039D8DA6</a>
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
	$msg = ""
	
	try
	{		
		$installVersion = $global:CoresightConfiguration.Version	
		
		$installVersionTokens = $installVersion.Split(".")
		# Form an integer value with all the version tokens.
		[string]$temp = $InstallVersionTokens[0] + $installVersionTokens[1] + $installVersionTokens[2] + $installVersionTokens[3]
		$installVersionInt64 = [Convert]::ToInt64($temp)
		if($installVersionInt64 -ge 3004)
		{
			$result = $true
			$msg = "Version is compliant."
		}	
		else 
		{
			$result = $false
			$msg = "Version is not compliant."
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table.
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU50001" `
									-aif $fn -msg $msg `
									-ain "PI Coresight Version" -aiv $result `
									-Group1 "PI System" -Group2 "PI Coresight" `
									-Severity "Moderate"																																																

}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckCoresightAppPools
{
<#  
.SYNOPSIS
AU50002 - Check Coresight AppPools identity
.DESCRIPTION
VALIDATION: checks PI Coresight AppPool identity.<br/>
COMPLIANCE: Use a custom domain account. Network Service is acceptable, but not ideal. 
For more information, see "Create a service account for PI Coresight" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-A790D013-BAC8-405B-A017-33E55595B411">https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-A790D013-BAC8-405B-A017-33E55595B411</a>
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
		$ServiceAppPoolType = $global:CoresightConfiguration.ServiceAppPoolType   # Service AppPool Identity Type
		$AdminAppPoolType = $global:CoresightConfiguration.AdminAppPoolType       # Admin AppPool Identity Type 
		$ServiceAppPoolUser = $global:CoresightConfiguration.ServiceAppPoolUser   # Service AppPool User
		$AdminAppPoolUser = $global:CoresightConfiguration.AdminAppPoolUser       # Admin AppPool User
		
		# Both Coresight AppPools must run under the same identity.
		If ( $ServiceAppPoolType -eq $AdminAppPoolType -and $ServiceAppPoolUser -eq $AdminAppPoolUser ) 
		{ 
			# If a custom account is used, we need to distinguish between a local and domain account.
			If ( $ServiceAppPoolType -eq "SpecificUser") 
			{
				# Local user would use ".\user" format.
				If ($ServiceAppPoolUser -contains ".\" ) 
				{ 
					$result = $false
					$msg =  "Local User is running Coresight AppPools. Please use a custom domain account."
				}
				Else # At this point, it's either a domain account or local account using "HOSTNAME\user" format. 
				{
					$hostname = $global:CoresightConfiguration.Hostname # Web Server Hostname
					# Extract the domain part from the AppPool identity string.
					$ServiceAppPoolUserDomain = $ServiceAppPoolUser.Split("\")[0]

					# Detect local user.
					If ($hostname -eq $ServiceAppPoolUserDomain)
					{
						$result = $false
						$msg =  "Local User is running Coresight AppPools. Please use a custom domain account."
					}
					Else # A custom domain account is used. 
					{
						$result = $true
						$msg =  "A custom domain account is running both Coresight AppPools"
					}
				}

			}
			ElseIf ($ServiceAppPoolType -eq "LocalSystem" ) # LocalSystem is running the Coresight AppPools. That's a bad idea.
			{ 
				$result = $false
				$msg =  "Local System is running both Coresight AppPools. Use a custom domain account instead."
			}
			Else # The only other options are: LocalService, NetworkService and AppPoolIdentity.  Pass and recommend domain account.
			{
				$result = $true
				$msg =  $ServiceAppPoolType + " is running the Coresight AppPools. Use a custom domain account instead."

			}
		}
		Else # For technical reasons, both Coresight AppPools must run under the same identity.
		{
			$result = $false
			$msg = "Both Coresight AppPools must run under the same identity."
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
									-at $AuditTable "AU50002" `
									-aif $fn -msg $msg `
									-ain "PI Coresight AppPool Check" -aiv $result `
									-Group1 "PI System" -Group2 "PI Coresight" `
									-Severity "Moderate"																																																
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CoresightSSLcheck
{
<#  
.SYNOPSIS
AU50003 - Coresight SSL check
.DESCRIPTION
VALIDATION: Checks whether SSL is enabled and enforced on the Coresight Web Site.<br/>
COMPLIANCE: A valid HTTPS binding is configured and only connections with SSL are allowed. The SSL certificate is issued by a Certificate Authority.
For more information, see "Configure Secure Sockets Layer (SSL) access" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-CB46B733-264B-48D3-9033-73D16B4DBD3B">https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-CB46B733-264B-48D3-9033-73D16B4DBD3B</a>
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
	$severity = "Unknown"
	try
	{	
		$CSwebSite = $global:CoresightConfiguration.WebSite # Web Site name
		$WebBindings = $global:CoresightConfiguration.Bindings # Web Site bindings
		$httpsBindingConfigured = $global:CoresightConfiguration.UsingHTTPS # Check if HTTPS binding is enabled.

		# HTTPS binding is disabled, so there's no point in checking anything else.
		If ($httpsBindingConfigured = $false) 
		{ 
			# Test fails, but how epic is the fail?
			$result = $false

			$basicAuth = $global:CoresightConfiguration.BasicAuthEnabled # Check if Basic Authentication is enabled.
			# Basic Authentication is disabled.
			If ($basicAuth.Value -eq $False) 
			{ 
				$severity = "Moderate" 
				$msg = "HTTPS binding is not enabled."
			} 
			Else # Basic Authentication is enabled and yet, SSL is not enabled. Epic fail.
			{ 
				$severity = "Severe"
				$msg = "Basic Authentication is enabled, but HTTPS binding is not enabled. User credentials sent over the wire are not encrypted!"
			}
		} 
		Else # HTTPS binding is enabled.
		{ 
			$SSLCheck_WebSite = $global:CoresightConfiguration.sslFlagsSite # SSL setting at Web Site level
			$SSLCheck_WebApp = $global:CoresightConfiguration.sslFlagsApp # SSL setting at Web App level

			# If either the Web Site OR Web App allows only connections with SSL, it's OK.
			If ($SSLCheck_WebSite.ToString() -eq "Ssl" -or $SSLCheck_WebApp.ToString() -eq "Ssl") 
			{ 
				# SSL is correctly configured. Let's check whether the SSL certificate is issued by a CA.
				$MachineDomain = $global:CoresightConfiguration.MachineDomain # Web Server Machine Domain
				$hostname = $global:CoresightConfiguration.Hostname # Web Server Hostname.

				# Build FQDN using hostname and domain strings.
				$fqdn = $hostname + "." + $machineDomain

				# Get the issuer of the SSL certificate used on the Coresight Web Site.
				$matches = [regex]::Matches($WebBindings, 'https \*:([0-9]+):') 
				
				# Go through all bindings.
				foreach ($match in $matches) {

					$port = $($match.Groups[1].Captures[0].Value)
					# Find SSL certificate for each binding of the PI Coresight Web Site.
					$portCert = Get-PISysAudit_BoundCertificate -lc $LocalComputer -rcn $RemoteComputerName -Port $port -DBGLevel $DBGLevel
					
					# Get the Thumbprint from all SSL certificates that have been found.
					$Thumbprint = $portCert[5].Split(":")[1].Trim()
					
					$sslissuer = Get-PISysAudit_CertificateProperty -lc $LocalComputer -rcn $RemoteComputerName -ct $Thumbprint -cp Issuer -DBGLevel $DBGLevel
					
					 # Certificate is self-signed (barring false positive).
					 # The Issuer is compared with the FQDN of the machine. This can lead to false positives (e.g. a leftover certificate from before the machine was renamed etc.)
					 If ($sslissuer.ToLower() -eq $fqdn.ToLower()) 
					 { 
						 $result = $false 
						 $severity = "Low"
						 $msg = "The SSL certificate is self-signed."
					 } 
					 Else # Certificate is issued by a CA (barring false positive).
					 { 
						 $result = $true 
						 $severity = "N/A"
						 $msg = "SSL is configured properly."
					 }

					If ( $result ) { break } # If at least one certificate is issued by a CA, pass.
				}
			} 	
			Else # HTTPS binding is enabled, but connections without SSL are allowed.
			{ 
				# Test fails, but how epic is the fail?
				$result = $false
				
				$basicAuth = $global:CoresightConfiguration.BasicAuthEnabled # Check if Basic Authentication is enabled.
				# Basic Authentication is disabled. Not too bad.
				If ($basicAuth.Value -eq $False) 
				{ 
					$severity = "Moderate" 
					$msg = "Connections without SSL are allowed."
				} 
				Else # Basic Authentication is enabled and yet, SSL is not enabled. Epic fail.
				{ 
					$severity = "Severe" 
					$msg = "Basic Authentication is enabled, but connections without SSL are allowed. User credentials sent over the wire may not be encrypted!"
				}
			}
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
									-at $AuditTable "AU50003" `
									-aif $fn -msg $msg `
									-ain "PI Coresight SSL Check" -aiv $result `
									-Group1 "PI System" -Group2 "PI Coresight" `
									-Severity $severity																																															
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CoresightSPNcheck
{
<#  
.SYNOPSIS
AU50004 - Coresight SPN check
.DESCRIPTION
VALIDATION: Checks PI Coresight SPN assignment. <br/>
COMPLIANCE: HTTP or HOST SPNs exist and are assigned to the Coresight AppPool account. This makes Kerberos Authentication possible.
For more information, see the PI Live Library link below. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-68329569-D75C-406D-AE2D-9ED512E74D46">https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v7/GUID-68329569-D75C-406D-AE2D-9ED512E74D46</a>
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
		$ServiceAppPoolType = $global:CoresightConfiguration.ServiceAppPoolType  # Service AppPool Identity Type 
		$ServiceAppPoolUser = $global:CoresightConfiguration.ServiceAppPoolUser  # Service AppPool User
		$CSwebSite = $global:CoresightConfiguration.WebSite  # Web Site Name
		$WebBindings = $global:CoresightConfiguration.Bindings # Web Site bindings.

		# Coresight is using the http service class.
		$serviceType = "http"

		# Special 'service name' for Coresight.
		# This is needed to distinguish between SPN check for IIS Apps such as Coresight, and Windows Services such as PI or AF.
		$serviceName = "coresight"

		# Converting the binding info to a string. Otherwise $matches based on RegExps are not returned correctly.
		$BindingsToString = $($WebBindings) | Out-String

		# Leverage WebBindings global variable and look for custom headers.
		$matches = [regex]::Matches($BindingsToString, ':{1}\d+:{1}(\S+)\s') 
				
		# Go through all bindings.
		foreach ($match in $matches) 
		{
			$CSheader = $match.Groups[1].Captures[0].Value 				
			If ($CSheader) # A custom host header is used!
			{ 
				$serviceName = "coresight_custom"
				break 
			}
		}

		# Coresight is running under a custom domain account.
		If ( $ServiceAppPoolType -eq "SpecificUser") 
		{ 
			$csappPool = $ServiceAppPoolUser 
		} 
		# Coresight is running under a machine account.
		Else 
		{ 
			$csappPool = $ServiceAppPoolType

			# Machine accounts don't need HTTP service class - it's already included in the HOST service class.
			$serviceType = "host"
		}
		
		$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $LocalComputer -rcn $RemoteComputerName -appPool $csappPool -CustomHeader $CSheader -dbgl $DBGLevel

		if($null -eq $result)
		{
			$msg = "Processing failed to parse setspn utility output."
			$result = "N/A"
		}
		Else
		{
			If ($result) 
			{ 
				$msg = "The Service Principal Name exists and it is assigned to the correct Service Account."
			} 
			Else 
			{ 			
				$msg = "The Service Principal Name does NOT exist or is NOT assigned to the correct Service Account."
			}	
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
									-at $AuditTable "AU50004" `
									-aif $fn -msg $msg `
									-ain "PI Coresight SPN Check" -aiv $result `
									-Group1 "PI System" -Group2 "PI Coresight" `
									-Severity "Moderate"																																																
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
function Get-PISysAudit_TemplateAU1xxxx
{
<#  
.SYNOPSIS
AU5xxxx - <Name>
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
		# Use information from $global:CoresightConfiguration whenever possible to 
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
									-at $AuditTable "AU1xxxx" `
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
Export-ModuleMember Get-PISysAudit_GlobalPICoresightConfiguration
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary5
Export-ModuleMember Get-PISysAudit_CheckCoresightVersion
Export-ModuleMember Get-PISysAudit_CheckCoresightAppPools
Export-ModuleMember Get-PISysAudit_CoresightSSLcheck
Export-ModuleMember Get-PISysAudit_CoresightSPNcheck
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU1xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU1xxxx