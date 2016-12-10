# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

function SetFolders
{
	# Retrieve the folder from which this script is called ..\Scripts and split the path
	# to remove the Scripts part.	
	$modulePath = $PSScriptRoot
	
	# ..\
	# ..\Scripts
	# ..\Scripts\PISYSAUDIT
	# ..\Export
	$scriptsPath = Split-Path $modulePath
	$rootPath = Split-Path $scriptsPath				
	
	$exportPath = PathConcat -ParentPath $rootPath -ChildPath "Export"
	if (!(Test-Path $exportPath)){
	New-Item $exportPath -type directory
	}

	$logFile = PathConcat -ParentPath $exportPath -ChildPath "PISystemAudit.log"		
	
	# Store at the global scope range.	
	New-Variable -Name "PISystemAuditLogFile" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $logFile	
}

Function Test-CoresightKerberosConfiguration {
<#  
.SYNOPSIS
Designed to check Coresight configuration to ensure Kerberos authentication and delegation
are configured correctly.  

.DESCRIPTION
Dubbed 'PI Dog' after Kerberos, the three-headed guardian of Hades.  PI Dog
has best support when run locally due to complications with WS-Man, SPN resolution or 
cross domain complications.
	
Import the PISYSAUDIT module to make this function available.

The syntax is...				 
Test-CoresightKerberosConfiguration [[-ComputerName | -cn] <string>]
.PARAMETER cn
The computer hosting the PI Coresight web application.
.EXAMPLE
Test-CoresightKerberosConfiguration -ComputerName piomnibox -KerberosCheck ResourceBased
.LINK
https://pisquare.osisoft.com
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("cn")]
		[string] $ComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("kc")]
		[ValidateSet('None','Classic','ResourceBased','Menu')]
		[string] $KerberosCheck = "Menu"		
	)	

# Read from the global constant bag.
if($null -ne (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value){ SetFolders }

$fn = GetFunctionName

if($KerberosCheck -eq 'Menu')
{
	$title = "PI DOG - Please run it locally on the PI Coresight server machine."
	$message = "PI Dog always fetches information about Coresight IIS settings and SPNs. Would you like to check Kerberos Delegation configuration as well?"

	$NoKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&No Kerberos delegation check", `
		"Doesn't check Kerberos Delegation Configuration."
	$ClassicKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&Classic Kerberos delegation check", `
		"Checks Classic Kerberos Configuration."
	$RBKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&Resource-Based Kerberos delegation check", `
		"Checks Resource-Based Kerberos Configuration."

	$options = [System.Management.Automation.Host.ChoiceDescription[]]($NoKerberos,$ClassicKerberos,$RBKerberos)

	$result = $host.ui.PromptForChoice($title, $message, $options, 0) 
}
else
{
	# Assign compatible result from friendly name
	switch($KerberosCheck)
	{
		'None' {$result = 0}
		'Classic' {$result = 1}
		'ResoureBased' {$result = 2}
	}
}

# Test non-local computer to validate if WSMan is working.
if($ComputerName -eq "")
{							
	$msgTemplate = "The server: {0} does not need WinRM communication because it will use a local connection"
	$msg = [string]::Format($msgTemplate, $ComputerName)
	Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1					
}
else
{								
	try
	{
		$resultWinRMTest = $null
		$resultWinRMTest = Test-WSMan -authentication default -ComputerName $ComputerName
		if($null -eq $resultWinRMTest)
		{
			$msgTemplate = "The server: {0} has a problem with WinRM communication"
			$msg = [string]::Format($msgTemplate, $ComputerName)
			Write-PISysAudit_LogMessage $msg "Error" $fn
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem has occurred during the validation with WSMan"						
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
	}						
}

switch ($result)
    {
		# Basic IIS Configuration checks only
        0 {"Kerberos Delegation configuration will not be checked."
			$blnDelegationCheckConfirmed = $false
			$rbkcd = $false
			$ADMtemp = $false
        }

		# Basic IIS checks + classic Kerberos delegation check (unconstrained delegation not supported!)
        1 {"Classic Kerberos Delegation configuration will be checked."
			$ADMtemp = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -eq 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbkcd = $false
        }

		# Basic IIS checks + resource based Kerberos constrained delegation check
        2 {"Resource-Based Kerberos Delegation configuration will be checked."
			$ADMtemp = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -eq 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbkcd = $true
        }
    }

# If needed, install 'Remote Active Directory Administration' PS Module.
If ($ADMtemp) {

	$titleRSAT = "RSAT-AD-PowerShell required"
	$messageRSAT = "'Remote Active Directory Administration' Module is required to proceed."

	$yesRSAT = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, install the module."
	$noRSAT = New-Object System.Management.Automation.Host.ChoiceDescription "&No, don't install the module and abort."
	$optionsRSAT = [System.Management.Automation.Host.ChoiceDescription[]]($yesRSAT,$noRSAT)

	$resultRSAT = $host.ui.PromptForChoice($titleRSAT, $messageRSAT, $optionsRSAT, 0) 

    If ($resultRSAT -eq 0) {
		Write-Output "Installation of 'Remote Active Directory Administration' module is about to start.."
		Add-WindowsFeature RSAT-AD-PowerShell
    }
		Else { Write-Output "'Remote Active Directory Administration' is required to check Kerberos Delegation settings. Aborting." 
		break
    }

}

# Initialize variables
$strSPNs = $null
$strBackEndSPNS = $null
$global:strIssues = $null
$global:issueCount = 0
$global:strRecommendations = $null
$global:strClassicDelegation = $null
$global:RBKCDstring = $null
$CoresightDelegation = $null
$RemoteComputerName = $ComputerName
If($ComputerName -eq ""){$LocalComputer = $true}
Else{$LocalComputer = $false}

# Get CoreSight Web Site Name
$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
$attribute = "WebSite"
$CSwebSite = Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -rkp $RegKeyPath -a $attribute -DBGLevel $DBGLevel	

# Get CoreSight Installation Directory
$RegKeyPath = "HKLM:\Software\PISystem\Coresight"
$attribute = "InstallationDirectory"
$CSInstallDir = Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -rkp $RegKeyPath -a $attribute -DBGLevel $DBGLevel	

# Get CoreSight Web Site name
$csWebAppQueryTemplate = "Get-WebApplication -Site `"{0}`""
$csWebAppQuery = [string]::Format($csWebAppQueryTemplate, $CSwebSite)
$csWebApp = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $csWebAppQuery -DBGLevel $DBGLevel
$csWebApp = $csWebApp | ? {$_.physicalPath -eq $CSInstallDir.TrimEnd("\")}

#Generate root path that's used to grab Web Configuration properties
$csAppPSPath = $csWebApp.pspath + "/" + $CSwebSite + $csWebApp.path

# Get CoreSight Service AppPool Identity Type
$QuerySvcAppPool = "Get-ItemProperty iis:\apppools\coresightserviceapppool -Name processmodel.identitytype"
$CSAppPoolSvc = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QuerySvcAppPool -DBGLevel $DBGLevel

# Get CoreSight Admin AppPool Identity Type
$QueryAdmAppPool = "Get-ItemProperty iis:\apppools\coresightadminapppool -Name processmodel.identitytype"
$CSAppPoolAdm = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QueryAdmAppPool -DBGLevel $DBGLevel

# Get CoreSight Admin AppPool Username
$QueryAdmUser = "Get-ItemProperty iis:\apppools\coresightadminapppool -Name processmodel.username.value"
$CSUserAdm = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QueryAdmUser -DBGLevel $DBGLevel

# Get CoreSight Service AppPool Username
$QuerySvcUser = "Get-ItemProperty iis:\apppools\coresightserviceapppool -Name processmodel.username.value"
$CSUserSvc = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QuerySvcUser -DBGLevel $DBGLevel
# Output to string for gMSA check
$CSUserGMSA = $CSUserSvc | Out-String

    # Check whether a custom account is used to run the Coresight Service AppPool
	# This doesn't take into account edge cases like LocalSystem as it's handled in the main Coresight module
    If ($CSAppPoolSvc -ne "NetworkService" -and $CSAppPoolSvc -ne "ApplicationPoolIdentity")
    {   # Custom account is used
        $blnCustomAccount = $true

		# Variable just for output.
		$CSAppPoolIdentity = $CSUserSvc
        
		# Custom account, but is it a gMSA?
        If ($CSUserGMSA.contains('$')) { $blngMSA = $True } 
		Else {   
			$blngMSA = $false 
            $global:strRecommendations += "`n Use a Group Managed Service Account. 
			For more information, see - https://blogs.technet.microsoft.com/askpfeplat/2012/12/16/windows-server-2012-group-managed-service-accounts."
        }

    }
    Else # Custom account is not used (so it cannot be a gMSA)
    {
            $blnCustomAccount = $false
            $blngMSA = $false
            $global:strRecommendations += "`n Use a Group Managed Service Account. 
			For more information, see - https://blogs.technet.microsoft.com/askpfeplat/2012/12/16/windows-server-2012-group-managed-service-accounts."
			
			# Variable just for output.
			$CSAppPoolIdentity = $CSAppPoolSvc
    }


    # Get Windows Authentication Property
    $blnWindowsAuthQueryTemplate = "Get-WebConfigurationProperty -PSPath `"{0}`" -Filter '/system.webServer/security/authentication/windowsAuthentication' -name enabled | select -expand Value"
    $blnWindowsAuthQuery = [string]::Format($blnWindowsAuthQueryTemplate, $csAppPSPath)
    $blnWindowsAuth = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $blnWindowsAuthQuery -DBGLevel $DBGLevel
    # Windows Authentication must be enabled - if it isn't, exit.
    if (!$blnWindowsAuth) { 
    Write-Output "Windows Authentication must be enabled!"
    break }

    # Get Windows Authentication Providers
    $authProviders = $(Get-WebConfigurationProperty -PSPath $csAppPSPath -Filter '/system.webServer/security/authentication/windowsAuthentication/providers' -Name *).Collection
    $strProviders = ""
    foreach($provider in $authProviders){$strProviders+="`r`n`t`t`t"+$provider.Value}
  
    # Get Kernel-mode authentication status
    $blnKernelModeQueryTemplate = "Get-WebConfigurationProperty -PSPath `"{0}`" -Filter '/system.webServer/security/authentication/windowsAuthentication' -name useKernelMode | select -expand Value"
    $blnKernelModeQuery = [string]::Format($blnKernelModeQueryTemplate, $csAppPSPath)
    $blnKernelMode = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $blnKernelModeQuery -DBGLevel $DBGLevel

    # Get UseAppPoolCredentials property
    $blnUseAppPoolCredentialsQueryTemplate = "Get-WebConfigurationProperty -PSPath `"{0}`" -Filter '/system.webServer/security/authentication/windowsAuthentication' -name useAppPoolCredentials | select -expand Value"
    $blnUseAppPoolCredentialsQuery = [string]::Format($blnUseAppPoolCredentialsQueryTemplate, $csAppPSPath)
    $blnUseAppPoolCredentials = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $blnUseAppPoolCredentialsQuery -DBGLevel $DBGLevel

	# Get Coresight Web Site bindings
	$WebBindingsQueryTemplate = "Get-WebBinding -Name `"{0}`""
	$WebBindingsQuery = [string]::Format($WebBindingsQueryTemplate, $CSwebSite)
	$CSWebBindings = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $WebBindingsQuery -DBGLevel $DBGLevel

    # Get the CoreSight web server hostname, domain name, and build the FQDN
    # $CSWebServerName = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName).ComputerName
    $CSWebServerName = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" "ComputerName" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
    $CSWebServerDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
    $CSWebServerFQDN = $CSWebServerName + "." + $CSWebServerDomain 

	# By default, assume custom header is not used.
	$blnCustomHeader = $false

	# Convert WebBindings to string and look for custom headers.
	$BindingsToString = $($CSWebBindings) | Out-String
	$matches = [regex]::Matches($BindingsToString, ':{1}\d+:{1}(\S+)\s') 
		foreach ($match in $matches) { 
			$CSheader = $match.Groups[1].Captures[0].Value 
				If ($CSheader) { 
				# A custom host header is used! The first result is taken.
				$CScustomHeader = $CSheader
				$blnCustomHeader = $true
				break 
				}
		}

          
              
		# Custom Host Header is used.
		If ($blnCustomHeader) {

				# Check whether the custom host header is a CNAME Alias or Host (A) DNS entry
				$AliasTypeCheck = Resolve-DnsName $CScustomHeader | Select -ExpandProperty Type

				# Custom Host header used for the Coresight Web Site is a CNAME
				If ($AliasTypeCheck -match "CNAME") { 
				$CNAME = $true 
				$CScustomHeaderType = "CNAME DNS Alias"
				# Host (A) DNS entry is preferred
				$global:strRecommendations += "`n Do NOT use CNAME aliases as Custom Host Headers. Use custom HOST (A) DNS entry instead."
				} 

				# Custom Host header used for the Coresight Web Sire is a Host (A) DNS record
				Else { 
				$CNAME = $false 
				$CScustomHeaderType = "HOST (A) DNS record"
				}

				# Find out whether the custom host header is using short or fully qualified domain name.
				If ($CScustomHeader -match "\.") 
				{
				# The specified custom host header is an FQDN
				$csCHeaderLong = $CScustomHeader
				$pos = $CScustomHeader.IndexOf(".")
				$csCHeaderShort = $CScustomHeader.Substring(0, $pos)
				} 
		
				Else { 
				# The specified custom host header is a short domain name.
				$csCHeaderShort = $CScustomHeader
				$csCHeaderLong = $CScustomHeader + "." + $CSWebServerDomain
				}

			   # Custom Account is running Coresight AppPools.
			   If ($blnCustomAccount) {
       
				   # Kernel-mode Authentication is enabled, but UseAppPoolCredentials property is FALSE.
				   If ($blnKernelMode -eq $True -and $blnUseAppPoolCredentials -eq $false) {
					$global:strIssues += "`n Kerberos Authentication will fail because Kernel-mode Authentication is enabled AND Custom Account is running Coresight, 
					BUT UseAppPoolCredentials property is set to FALSE. Change it to TRUE. For more information, see http://aka.ms/kcdpaper"
					$global:issueCount += 1
				   }
                
				   # Kernel-mdoe Authentication is disabled.
				   ElseIf ($blnKernelMode -eq $false) {
				   $global:strRecommendations += "`n ENABLE Kernel-mode Authentication and set UseAppPoolCredentials property to TRUE."
				   }

				   # Kernel-mode Authentication is enabled, and UseAppPoolCredentials property is TRUE. Great!
				   Else { }

						# SPN check
						$spnCheck = $(setspn -l $CSUserSvc).ToLower()
						$spnCounter = 0

							# CNAME is used.
							If ($CNAME) {
							$hostnameSPN = $("http/" + $CSWebServerName.ToLower())
							$fqdnSPN = $("http/" + $CSWebServerFQDN.ToLower())
			
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$hostnameSPN {$spnCounter++; break}
										$fqdnSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $hostnameSPN and $fqdnSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. Please make sure $hostnameSPN and $fqdnSPN SPNs are created.
									For more information, see: https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-799220A0-4967-45CE-A592-45E3FC10C752"
									$global:issueCount += 1
									}

							}
                    
							# Host (A)
							Else {


							$csCHeaderSPN = $("http/" + $csCHeaderShort.ToLower())
							$csCHeaderLongSPN = $("http/" + $csCHeaderLong.ToLower())
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$csCHeaderSPN {$spnCounter++; break}
										$csCHeaderLongSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $csCHeaderSPN and $csCHeaderLongSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. 
									Please make sure $csCHeaderSPN and $csCHeaderLongSPN SPNs are created.
									For more information, see: https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-799220A0-4967-45CE-A592-45E3FC10C752"
									$global:issueCount += 1
									}

							}


                
					}

					# Machine Account is running Coresight AppPools.
					Else {
					If ($blnKernelMode -ne $True) {
					$global:strRecommendations += "`n ENABLE Kernel-mode Authentication."
					}
            
						# SPN check
						$spnCheck = $(setspn -l $CSWebServerName).ToLower()
						$spnCounter = 0

							# CNAME is used.
							If ($CNAME) {
							$hostnameSPN = $("host/" + $CSWebServerName.ToLower())
							$fqdnSPN = $("host/" + $CSWebServerFQDN.ToLower())
			
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$hostnameSPN {$spnCounter++; break}
										$fqdnSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $hostnameSPN and $fqdnSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. 
									Please make sure $hostnameSPN and $fqdnSPN SPNs are created.
									For more information, see: https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-799220A0-4967-45CE-A592-45E3FC10C752"
									$global:issueCount += 1
									}

							}
                    
							# Host (A)
							Else {


							$csCHeaderSPN = $("http/" + $csCHeaderShort.ToLower())
							$csCHeaderLongSPN = $("http/" + $csCHeaderLong.ToLower())
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$csCHeaderSPN {$spnCounter++; break}
										$csCHeaderLongSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $csCHeaderSPN and $csCHeaderLongSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. 
									Please make sure $csCHeaderSPN and $csCHeaderLongSPN SPNs are created. 
									For more information, see: https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-799220A0-4967-45CE-A592-45E3FC10C752 "
									$global:issueCount += 1
									}

							}

					}

			   }
		# Custom Host Header is NOT used.
		Else {
			   $global:strRecommendations += "`n Use Custom Host Header (Name) in $CSWebSiteName web site bindings."


				   If ($blnCustomAccount) {
						# Kernel-mode Authentication is enabled, but UseAppPoolCredentials property is FALSE.
						If ($blnKernelMode -eq $True -and $blnUseAppPoolCredentials -eq $false) {
						$global:strIssues += "`n Kerberos Authentication will fail because Kernel-mode Authentication is enabled AND Custom Account is running Coresight, 
						BUT UseAppPoolCredentials property is set to FALSE. Change it to TRUE. For more information, see http://aka.ms/kcdpaper"
						$global:issueCount += 1
						}
						# Kernel-mdoe Authentication is disabled.
						ElseIf ($blnKernelMode -eq $false) {
						$global:strRecommendations += "`n ENABLE Kernel-mode Authentication and set UseAppPoolCredentials property to TRUE. For more information, see http://aka.ms/kcdpaper"
						}
						# Kernel-mode Authentication is enabled, and UseAppPoolCredentials property is TRUE. Great!
						Else {
						# All good.
						}

						#SPN check
						$spnCheck = $(setspn -l $CSUserSvc).ToLower()
						$spnCounter = 0
                    
							$hostnameSPN = $("http/" + $CSWebServerName.ToLower())
							$fqdnSPN = $("http/" + $CSWebServerFQDN.ToLower())
			
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$hostnameSPN {$spnCounter++; break}
										$fqdnSPN {$spnCounter++; break}
										default {break}
									}
								}

									If ($spnCounter -eq 2) { 
									$strSPNs = "Service Principal Names are configured correctly: $hostnameSPN and $fqdnSPN"                            
									}
									Else {
									$strSPNs = "Unable to find all required HTTP SPNs."
									$global:strIssues += "`n Unable to find all required HTTP SPNs. 
									Please make sure $hostnameSPN and $fqdnSPN SPNs are created. For more information, see https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-68329569-D75C-406D-AE2D-9ED512E74D46 "
									$global:issueCount += 1
									}
					}
					Else {
						#$global:strRecommendations += "`n Use Custom Domain Account to run Coresight AppPools. Ideally, use a (Group) Managed Service Account."
						If (!$blnKernelMode) {
							$global:strRecommendations += "`n ENABLE Kernel-mode Authentication."
						}
						

						$spnCheck = $(setspn -l $CSWebServerName).ToLower()
						$spnCounter = 0
                    
							$hostnameSPN = $("host/" + $CSWebServerName.ToLower())
							$fqdnSPN = $("host/" + $CSWebServerFQDN.ToLower())
			
								foreach($line in $spnCheck)
								{
									switch($line.ToLower().Trim())
									{
										$hostnameSPN {$spnCounter++; break}
										$fqdnSPN {$spnCounter++; break}
										default {break}
									}
								}
								
								# Both SPNs must exist
								If ($spnCounter -eq 2) { 
								$strSPNs = "Service Principal Names are configured correctly: $hostnameSPN and $fqdnSPN"                            
								}
								
								# Some SPN(s) is (are) missing
								Else {
								$strSPNs = "Unable to find all required HTTP SPNs."
								$global:strIssues += "`n Unable to find all required HTTP SPNs. 
								Please make sure $hostnameSPN and $fqdnSPN SPNs are created. For more information, see https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-68329569-D75C-406D-AE2D-9ED512E74D46 "
								$global:issueCount += 1
								}

				   }
			   }

		# KERBEROS DELEGATION CHECK IS CONFIRMED
		If ($blnDelegationCheckConfirmed) {
				   
					# Get PI and AF Servers from the web server KST
					$AFServers = Get-KnownServers -lc $LocalComputer -rcn $RemoteComputerName -st AFServer 
					$PIServers = Get-KnownServers -lc $LocalComputer -rcn $RemoteComputerName -st PIServer
					# RESOURCE BASED KERBEROS DELEGATION
				   If ($rbkcd) {

						If (!$blnCustomAccount) { $RBKCDAppPoolIdentity = $CSWebServerName }
						Else {
						$RBKCDAppPoolIdentityPos = $CSUserSvc.IndexOf("\")
						$RBKCDAppPoolIdentity = $CSUserSvc.Substring($RBKCDAppPoolIdentityPos+1)
						$RBKCDAppPoolIdentity = $RBKCDAppPoolIdentity.TrimEnd('$')
						}
						
								foreach ($AFServerTemp in $AFServers) { 
									$AFServer = $AFServerTemp.Groups[1].Captures[0].Value
									$AFSvcAccount = Get-PISysAudit_ServiceLogOnAccount "afservice" -lc $false -rcn $AFServer -ErrorAction SilentlyContinue
									#Write-Host "DEBUG $value"
									If ($AFSvcAccount -ne $null ) { 
									If ($AFSvcAccount -eq "LocalSystem" -or $AFSvcAccount -eq "NetworkService") { $AFSvcAccount = $AFServer }
									$RBKCDpos = $AFSvcAccount.IndexOf("\")
									$AFSvcAccount = $AFSvcAccount.Substring($RBKCDpos+1)
									$AFSvcAccount = $AFSvcAccount.TrimEnd('$')

									$DomainObjectType = Get-ADObject -Filter { Name -like $AFSvcAccount } -Properties ObjectCategory | Select -ExpandProperty objectclass
									If ($DomainObjectType -eq "user") { $AccType = 1 } ElseIf ($DomainObjectType -eq "computer") { $AccType = 2 } ElseIf ($DomainObjectType -eq "msDS-GroupManagedServiceAccount" -or $DomainObjectType -eq "msDS-ManagedServiceAccount") {  $AccType = 3 } Else { "Unable to locate ADObject $DomainObjectType." }

									If ($AccType -eq 1) { 
									$RBKCDPrincipal = Get-ADUser $AFSvcAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
										If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to AF Server $AFServer running under $AFSvcAccount"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to AF Server $AFServer running under $AFSvcAccount"
										}
									}


									If ($AccType -eq 2) { 
									$RBKCDPrincipal = Get-ADComputer $AFSvcAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
										If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to AF Server $AFServer running under $AFSvcAccount"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to AF Server $AFServer running under $AFSvcAccount"
										}
									}


									If ($AccType -eq 3) { 
									$RBKCDPrincipal = Get-ADServiceAccount $AFSvcAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
										If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to AF Server $AFServer running under $AFSvcAccount"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to AF Server $AFServer running under $AFSvcAccount"
										}
									}

									}
									Else { 
									$global:RBKCDstring += "`n Could not get the service account running AF Server. Please make sure AF Server $AFServer is configured for PSRemoting.
									https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS) `n "
									}

								}

								foreach ($PIServer in $PIServers) { 
									$PISvcAccount = Get-PISysAudit_ServiceLogOnAccount "pinetmgr" -lc $false -rcn $PIServer -ErrorAction SilentlyContinue
									If ($PISvcAccount -ne $null ) { 
									If ($PISvcAccount -eq "LocalSystem" -or $PISvcAccount -eq "NetworkService") { $PISvcAccount = $PIServer }
									$RBKCDpos = $PISvcAccount.IndexOf("\")
									$PISvcAccount = $PISvcAccount.Substring($RBKCDpos+1)
									$PISvcAccount = $PISvcAccount.TrimEnd('$')

									$DomainObjectType = Get-ADObject -Filter { Name -like $PISvcAccount } -Properties ObjectCategory | Select -ExpandProperty objectclass
									If ($DomainObjectType -eq "user") { $AccType = 1 } ElseIf ($DomainObjectType -eq "computer") { $AccType = 2 } ElseIf ($DomainObjectType -eq "msDS-GroupManagedServiceAccount" -or $DomainObjectType -eq "msDS-ManagedServiceAccount") {  $AccType = 3 } Else { "Unable to locate ADObject $DomainObjectType." }


									If ($AccType -eq 1) { 
									$RBKCDPrincipal = Get-ADUser $PISvcAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
										If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to PI Server $PIServer running under $PISvcAccount"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to PI Server $PIServer running under $PISvcAccount"
										}
									}


									If ($AccType -eq 2) { 
									$RBKCDPrincipal = Get-ADComputer $PISvcAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
									If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to PI Server $PIServer running under $PISvcAccount"
										} 
										Else { 
										$global:RBKCDstring += "`n $RBKCDAppPoolIdentity CAN'T delegate to PI Server $PIServer running under $PISvcAccount"
										}
									}


									If ($AccType -eq 3) { 
									$RBKCDPrincipal = Get-ADServiceAccount $PISvcAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount
									If ($RBKCDPrincipal -match $RBKCDAppPoolIdentity) { 
									$global:RBKCDstring += "`n $RBKCDAppPoolIdentity can delegate to PI Server $PIServer running under $PISvcAccount" }
									}

									}
									Else { 
									$global:RBKCDstring += "`n Could not get the service account running AF Server. Please make sure PI Server $PIServer is configured for PSRemoting.
									https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS) `n "
									}


								}
						# New variable for easy output
						$CoresightDelegation = $global:RBKCDstring
						}

				   # CLASSIC KERBEROS DELEGATION
				   Else {
					$PIServers = Get-KnownServers -lc $LocalComputer -rcn $RemoteComputerName -st PIServer
					$AFServers = Get-KnownServers -lc $LocalComputer -rcn $RemoteComputerName -st AFServer
            
					<#$global:strRecommendations += "`n ENABLE Kerberos Resource Based Constrained Delegation. 
					`n For more information, please check OSIsoft KB01222 - Types of Kerberos Delegation
					   http://techsupport.osisoft.com/Troubleshooting/KB/KB01222 `n"#>

					If ($CSAppPoolSvc -eq "NetworkService") { $CSUserSvc = $CSWebServerName  }
						If ($blnCustomAccount) { 
							If ($blngMSA) { 
							$posAppPool = $CSUserSvc.IndexOf("\")
							$CSUserSvc = $CSUserSvc.Substring($posAppPool+1)
							$CSUserSvc = $CSUserSvc.TrimEnd('$')
							}
							Else { 
							$posAppPool = $CSUserSvc.IndexOf("\")
							$CSUserSvc = $CSUserSvc.Substring($posAppPool+1)
							}
						}
            
								$AppAccType = Get-ADObject -Filter { Name -like $CSUserSvc } -Properties ObjectCategory | Select -ExpandProperty objectclass
								If ($AppAccType -eq "user") { $AccType = 1 } ElseIf ($AppAccType -eq "computer") { $AccType = 2 } ElseIf ($AppAccType -eq "msDS-GroupManagedServiceAccount" -or $AppAccType -eq "msDS-ManagedServiceAccount"  ) {  $AccType = 3 } 
								Else { "Unable to locate ADObject $AppAccType." 
								break
								}
            
								If ($AccType -eq 1) {
								$AppPoolDelegation = Get-ADUser $CSUserSvc -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
								$ProtocolTransition = Get-ADUser $CSUserSvc -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
								$UnconstrainedKerberos = Get-ADUser $CSUserSvc -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
								}


								If ($AccType -eq 2) { 
								$AppPoolDelegation = Get-ADComputer $CSUserSvc -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
								$ProtocolTransition = Get-ADComputer $CSUserSvc -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
								$UnconstrainedKerberos = Get-ADComputer $CSUserSvc -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
								}


								If ($AccType -eq 3) { 
								$AppPoolDelegation = Get-ADServiceAccount $CSUserSvc -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
								$ProtocolTransition = Get-ADServiceAccount $CSUserSvc -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
								$UnconstrainedKerberos = Get-ADServiceAccount $CSUserSvc -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
								}


							   If ($UnconstrainedKerberos -eq $true) { 
							   $global:strIssues += "`n Unconstrained Kerberos Delegation is enabled on $CSUserSvc. This is neither secure nor supported. 
							   `n Enable Constrained Kerberos Delegation instead. See OSIsoft KB01222 - Types of Kerberos Delegation
							   `n http://techsupport.osisoft.com/Troubleshooting/KB/KB01222           
							   `n Aborting."
							   $global:issueCount += 1
							   $global:strIssues
							   break
							   }


								# Get Domain info.
								$CSWebServerDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $LocalComputer -dbgl $DBGLevel


								# Delegation
								If ($AppPoolDelegation -ne $null) { 
								$DelegationSPNList = $AppPoolDelegation.ToLower().Trim() 
								$dot = '.'
								$PISPNClass = "piserver/"
								$AFSPNClass = "afserver/"
									# DELEGATION TO PI
									foreach ($PIServer in $PIServers) {

        
										If ($PIServer -match [regex]::Escape($dot)) { 
										# FQDN
										$fqdnPI = $PIServer.ToLower() 
										$pos = $fqdnPI.IndexOf(".")
										$shortPI = $fqdnPI.Substring(0, $pos)
										}
         
										Else { 
										#SHORT
										$shortPI = $PIServer.ToLower() 
										$fqdnPI = ($PIServer.ToLower() + "." + $CSWebServerDomain.ToLower()).ToString()
										}

									   # Check if delegation is enabled.
									   $shortPISPN = ($PISPNClass + $shortPI).ToString()
									   $longPISPN = ($PISPNClass + $fqdnPI).ToString()
									   If ($DelegationSPNList -match $shortPISPN -and $DelegationSPNList -match $longPISPN ) { 
									   $global:strClassicDelegation += "`n Coresight can delegate to PI Server: $PIServer" 
									   }
									   Else { 
									   $global:strClassicDelegation += "`n Coresight can't delegate to PI Server: $PIServer" 
									   }


									}

										# DELEGATION TO AF
										foreach ($AFServerTemp in $AFServers) {
										$AFServer = $AFServerTemp.Groups[1].Captures[0].Value
										If ($AFServer -match [regex]::Escape($dot)) { 
										# FQDN
										$fqdnAF = $AFServer.ToLower() 
										$pos = $fqdnAF.IndexOf(".")
										$shortAF = $fqdnAF.Substring(0, $pos)
										}
         
										Else { 
										#SHORT
										$shortAF = $AFServer.ToLower() 
										$fqdnAF = ($AFServer.ToLower() + "." + $CSWebServerDomain.ToLower()).ToString()
										}

									   # Check if delegation is enabled.
									   $shortAFSPN = ($AFSPNClass + $shortAF).ToString()
									   $longAFSPN = ($AFSPNClass + $fqdnAF).ToString()
									   If ($DelegationSPNList -match $shortAFSPN -and $DelegationSPNList -match $longAFSPN ) { 
									   $global:strClassicDelegation += "`n Coresight can delegate to AF Server: $AFServer" 
									   }
									   Else { 
									   $global:strClassicDelegation += "`n Coresight can't delegate to AF Server: $AFServer" 
									   }


									}


												} 
								Else { Write-Output "Kerberos Deleagation is not configured.
													`n Enable Constrained Kerberos Delegation instead. See OSIsoft KB01222 - Types of Kerberos Delegation
													`n http://techsupport.osisoft.com/Troubleshooting/KB/KB01222" 
								}

						$CoresightDelegation = $global:strClassicDelegation
						}


				## BACK-END SERVICES SERVICE PRINCIPAL NAME CHECK
				foreach ($AFServerBEC in $AFServers) {
					$AFServer = $AFServerBEC.Groups[1].Captures[0].Value
					$serviceType = "afserver"
					$serviceName = "afservice"
					$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $false -rcn $AFServer -dbgl $DBGLevel
					If ($result) { $strBackEndSPNS += "`n Service Principal Names for AF Server $AFServer are set up correctly." }
					Else { $strBackEndSPNS += "`n Service Principal Names for AF Server $AFServer are NOT set up correctly." }
				}

				foreach ($PIServerBEC in $PIServers) {
					$serviceType = "piserver"
					$serviceName = "pinetmgr"
					$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $false -rcn $PIServerBEC -dbgl $DBGLevel
					If ($result) { $strBackEndSPNS += "`n Service Principal Names for PI Server $PIServerBEC are set up correctly." }
					Else { $strBackEndSPNS += "`n Service Principal Names for PI Server $PIServerBEC are NOT set up correctly." }
				}
			}


#### Summary
$LogFile="CoresightKerberosConfig.log"
$strSummaryReport = @"
    Coresight Authentication Settings:
        Is Windows Authentication Enabled: {0}
        Windows Authentication Providers: {1}
        Kernel-mode Authentication Enabled: {2}
        UseAppPoolCredentials property: {3}
        `n
    Coresight Web Site Bindings:
        Is Custom Host Header used: {4}
		Custom Host Header name: {5}
		Custom Host Header type: {6}
        `n
    Coresight AppPool Identity: {7}
        Group Managed Service Account used: {8}
        `n
    Coresight - Service Principal Names: {9}
        `n
	PI/AF - Service Principal Names: {10}
       `n
    Coresight - Kerberos Delegation: {11}
        `n
	RECOMMENDATIONS: {12}
        `n
	NUMBER OF ISSUES FOUND: {13}
        `n
	ISSUES - DETAILS: {14}
        `n
"@ -f $blnWindowsAuth, $strProviders, $blnKernelMode, $blnUseAppPoolCredentials, $blnCustomHeader, $CScustomHeader, $CScustomHeaderType, $CSAppPoolIdentity, $blngMSA, $strSPNs, $strBackEndSPNS, $CoresightDelegation, $global:strRecommendations, $global:issueCount, $global:strIssues  

Write-Output $strSummaryReport
$strSummaryReport | Out-File $LogFile
}

Function Get-KnownServers
{
	param(
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer,
		[parameter(Mandatory=$true, Position=1, ParameterSetName = "Default")]		
		[alias("rcn")]
		[string]
		$RemoteComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("st")]
		[ValidateSet('PIServer','AFServer')]
		[string] $ServerType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	$fn = GetFunctionName

	If($ServerType -eq 'PIServer')
	{
		# Get PI Servers
		$regpathKST = 'HKLM:\SOFTWARE\PISystem\PI-SDK\1.0\ServerHandles'
		if($LocalComputer)
		{
			$KnownServers = Get-ChildItem $regpathKST | ForEach-Object {Get-ItemProperty $_.pspath} | where-object {$_.path} | Foreach-Object {$_.path}
		}
		Else
		{
			$scriptBlockCmdTemplate = "Get-ChildItem `"{0}`" | ForEach-Object [ Get-ItemProperty `$_.pspath ] | where-object [ `$_.path ] | Foreach-Object [ `$_.path ]"
			$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $regpathKST)
			$scriptBlockCmd = ($scriptBlockCmd.Replace("[", "{")).Replace("]", "}")			
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )													
			$KnownServers = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock 
		}
	}
	Else
	{
		# Get AF Servers
		$programDataWebServer = Get-PISysAudit_EnvVariable "ProgramData" -lc $LocalComputer -rcn $RemoteComputerName
		$afsdkConfigPathWebServer = "$programDataWebServer\OSIsoft\AF\AFSDK.config"
		if($LocalComputer)
		{
			$AFSDK = Get-Content -Path $afsdkConfigPathWebServer | Out-String
		}
		Else
		{
			$scriptBlockCmdTemplate = "Get-Content -Path ""{0}"" | Out-String"
			$scriptBlockCmd = [string]::Format($scriptBlockCmdTemplate, $afsdkConfigPathWebServer)									
			
			# Verbose only if Debug Level is 2+
			$msgTemplate = "Remote command to send to {0} is: {1}"
			$msg = [string]::Format($msgTemplate, $RemoteComputerName, $scriptBlockCmd)
			Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
			
			$scriptBlock = [scriptblock]::create( $scriptBlockCmd )
			$AFSDK = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock
		}
		$KnownServers = [regex]::Matches($AFSDK, 'host=\"([^\"]*)')
	}
	return $KnownServers
}

Export-ModuleMember -Function Test-CoresightKerberosConfiguration
Set-Alias -Name Unleash-PI_Dog -Value Test-CoresightKerberosConfiguration -Description “Sniff out Kerberos issues.”
Export-ModuleMember -Alias Unleash-PI_Dog