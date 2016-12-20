﻿# ........................................................................
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
	if($null -eq (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
	{
		New-Variable -Name "ExportPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $exportPath
	}
	if($null -eq (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
	{
		New-Variable -Name "PISystemAuditLogFile" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $logFile	
	}
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
		$programDataWebServer = Get-PISysAudit_EnvVariable "ProgramData" -lc $LocalComputer -rcn $RemoteComputerName  -Target Process
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

	$msgTemplate = "Known servers found: {0}"
	$msg = [string]::Format($msgTemplate, $KnownServers)
	Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

	return $KnownServers
}

function Get-ServiceLogonAccountType 
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sa")]
		[string]
		$ServiceAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("sad")]
		[string]
		$ServiceAccountDomain = $null,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cn")]
		[string]
		$ComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	$fn = GetFunctionName

	If ($ServiceAccount -eq "LocalSystem" -or $ServiceAccount -eq "NetworkService" `
		-or $ServiceAccount -eq "NT AUTHORITY\LocalSystem" -or $ServiceAccount -eq "NT AUTHORITY\NetworkService" `
		-or $ServiceAccount -eq "NT SERVICE\AFService") { $ServiceAccount = $ComputerName }
	$RBKCDpos = $ServiceAccount.IndexOf("\")
	$ServiceAccount = $ServiceAccount.Substring($RBKCDpos+1)
	$ServiceAccount = $ServiceAccount.TrimEnd('$')

	If($null -eq $ServiceAccountDomain -or $ServiceAccountDomain -eq '.' -or $ServiceAccountDomain -eq '')
	{
		$DomainObjectType = Get-ADObject -Filter { Name -like $ServiceAccount } -Properties ObjectCategory | Select -ExpandProperty objectclass
		$msgTemplate = "Querying AD for {0}"
		$msg = [string]::Format($msgTemplate, $ServiceAccount)
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
	}
	Else
	{
		$DomainObjectType = Get-ADObject -Filter { Name -like $ServiceAccount } -Properties ObjectCategory -Server $ServiceAccountDomain | Select -ExpandProperty objectclass
		$msgTemplate = "Querying AD for {0} in domain {1}"
		$msg = [string]::Format($msgTemplate, $ServiceAccount, $ServiceAccountDomain)
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
	}

	If ($DomainObjectType -eq "user") { $AccType = 1 } ElseIf ($DomainObjectType -eq "computer") { $AccType = 2 } ElseIf ($DomainObjectType -eq "msDS-GroupManagedServiceAccount" -or $DomainObjectType -eq "msDS-ManagedServiceAccount") {  $AccType = 3 } Else { $AccType = 0 }

	return $AccType
}

Function Get-ServiceLogonAccountDomain
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sa")]
		[string]
		$ServiceAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	$fn = GetFunctionName

	If ($ServiceAccount -eq "LocalSystem" -or $ServiceAccount -eq "NetworkService" `
		-or $ServiceAccount -eq "NT AUTHORITY\LocalSystem" -or $ServiceAccount -eq "NT AUTHORITY\NetworkService" `
		-or $ServiceAccount -eq "ApplicationPoolIdentity" `
		-or $ServiceAccount -eq "NT SERVICE\AFService") { $ServiceAccountDomain = $null}
	Else{
		$RBKCDpos = $ServiceAccount.IndexOf("\")
		If($RBKCDpos -eq -1){ $ServiceAccountDomain = $null }
		Else{ $ServiceAccountDomain = $ServiceAccount.Substring(0,$RBKCDpos) }
	}
	return $ServiceAccountDomain
}

Function Check-ResourceBasedConstrainedDelegationPrincipals 
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sa")]
		[string]
		$ServiceAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("sad")]
		[string]
		$ServiceAccountDomain = $null,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("sat")]
		[int]
		$ServiceAccountType = 0,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("api")]
		[string]
		$ApplicationPoolIdentity,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cn")]
		[string]
		$ComputerName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("rt")]
		[string]
		$ResourceType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	If ($ServiceAccount -eq "LocalSystem" -or $ServiceAccount -eq "NetworkService" `
		-or $ServiceAccount -eq "NT AUTHORITY\LocalSystem" -or $ServiceAccount -eq "NT AUTHORITY\NetworkService" `
		-or $ServiceAccount -eq "NT SERVICE\AFService")  { $ServiceAccount = $ComputerName }
	Else
	{
		$RBKCDpos = $ServiceAccount.IndexOf("\")
		$ServiceAccount = $ServiceAccount.Substring($RBKCDpos+1)
		$ServiceAccount = $ServiceAccount.TrimEnd('$')
	}

	$msgCanDelegateTo = "`n $global:CoresightAppPoolAccountPretty can delegate to $ResourceType $ComputerName running under $ServiceAccount"
	$msgCanNotDelegateTo = "`n $global:CoresightAppPoolAccountPretty CAN'T delegate to $ResourceType $ComputerName running under $ServiceAccount"
	$RBKCDPrincipal = ""
	$blnResolveDomain = $null -eq $ServiceAccountDomain -or $ServiceAccountDomain -eq ""

	If ($AccType -eq 1) 
	{ 
		if($blnResolveDomain){ $RBKCDPrincipal = Get-ADUser $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount }
		Else{ $RBKCDPrincipal = Get-ADUser $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount -Server $ServiceAccountDomain | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount }
	}
	If ($AccType -eq 2) { 
		if($blnResolveDomain){ $RBKCDPrincipal = Get-ADComputer $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount }
		Else{ $RBKCDPrincipal = Get-ADComputer $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount -Server $ServiceAccountDomain | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount }
	}
	If ($AccType -eq 3) { 
		if($blnResolveDomain){ $RBKCDPrincipal = Get-ADServiceAccount $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount }
		Else{ $RBKCDPrincipal = Get-ADServiceAccount $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount -Server $ServiceAccountDomain | Select -ExpandProperty PrincipalsAllowedToDelegateToAccount }
	}

	$msgTemplate = "Principals for Account {0} (Type:{1}): {2}"
	$msg = [string]::Format($msgTemplate, $ServiceAccount, $AccType, $RBKCDPrincipal)
	Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

	# Check the Principals for a match
	If ($RBKCDPrincipal -match $global:CoresightAppPoolAccount) { 
		$global:RBKCDstring += $msgCanDelegateTo
	} 
	Else { 
		$global:RBKCDstring += $msgCanNotDelegateTo
	}

}

Function Check-ClassicDelegation
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sspn")]
		[string]
		$ClassicShortSPN,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("lspn")]
		[string]
		$ClassicLongSPN,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cap")]
		[string]
		$ClassicAppPool,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("crt")]
		[string]
		$ClassicResourceType,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cse")]
		[string]
		$ClassicServer,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cat")]
		[int]
		$ClassicAccType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	# The list of SPNs Coresight AppPool can delegate to AND Protocol Transition property need to be retrieved only once.
	If ($ClassicAppPoolDelegation -eq $null) {
		If ($ClassicAccType -eq 1) {
		$ClassicAppPoolDelegation = Get-ADUser $ClassicAppPool -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
		$ClassicProtocolTransition = Get-ADUser $ClassicAppPool -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
		$ClassicUnconstrainedKerberos = Get-ADUser $ClassicAppPool -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
		}

		If ($ClassicAccType -eq 2) { 
		$ClassicAppPoolDelegation = Get-ADComputer $ClassicAppPool -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
		$ClassicProtocolTransition = Get-ADComputer $ClassicAppPool -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
		$ClassicUnconstrainedKerberos = Get-ADComputer $ClassicAppPool -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
		}

		If ($ClassicAccType -eq 3) { 
		$ClassicAppPoolDelegation = Get-ADServiceAccount $ClassicAppPool -Properties msDS-AllowedToDelegateTo | Select -ExpandProperty msDS-AllowedToDelegateTo
		$ClassicProtocolTransition = Get-ADServiceAccount $ClassicAppPool -Properties TrustedToAuthForDelegation | Select -ExpandProperty TrustedToAuthForDelegation
		$ClassicUnconstrainedKerberos = Get-ADServiceAccount $ClassicAppPool -Properties TrustedForDelegation | Select -ExpandProperty TrustedForDelegation
		}
		# Protocol transition messaging.
		If ($ClassicProtocolTransition -eq $true) { $KerbProtocolTransition = "ENABLED" }
		Else { $KerbProtocolTransition = "DISABLED" 
		$global:strClassicDelegation += "`n Protocol Transition is Disabled - Kerberos Delegation may fail. For details, see:
										`n https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-68329569-D75C-406D-AE2D-9ED512E74D46"
		}
	}

	# Unconstrained Kerberos Delegation is not supported (and rather insecure) > break.
	If ($ClassicUnconstrainedKerberos -eq $true) { 
	$global:strClassicDelegation = "`n Coresight AppPool Identity $ClassicAppPool is trusted for Unconstrained Kerberos Delegation. 
	`n This is neither supported nor secure.
	`n Enable Constrained Kerberos Delegation as per OSIsoft KB01222 - Types of Kerberos Delegation
	`n http://techsupport.osisoft.com/Troubleshooting/KB/KB01222           
	`n Aborting."
	 break
	 }

	# If the Constrained Kerberos Delegation list of SPN is STILL empty, no delegation is configured.			
	If ($ClassicAppPoolDelegation -eq $null ) {
	$global:strClassicDelegation = "`n Coresight AppPool Identity $ClassicAppPool is not trusted for Classic Constrained Kerberos Delegation. 
	`n Perhaps Resource Based Kerberos Delegation is enabled?
	`n Otherwise enable Constrained Kerberos Delegation as per OSIsoft KB01222 - Types of Kerberos Delegation
	`n http://techsupport.osisoft.com/Troubleshooting/KB/KB01222           
	`n Aborting."
	 break
	}
	
	# Delegation is enabled > convert to a string of lowercase characters.
	$ClassicDelegationList = $ClassicAppPoolDelegation.ToLower().Trim()	

	# Debug option.
	$msgTemplate = "Coresight AppPool Identity {0} can delegate to {1}"
	$msg = [string]::Format($msgTemplate, $CSUserSvc, $ClassicDelegationList)
	Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2



	$msgCanDelegateToClassic = "`n Coresight AppPool Identity $ClassicAppPool can delegate to $ClassicResourceType $ClassicServer."
	$msgCanNotDelegateToClassic = "`n Coresight AppPool Identity $ClassicAppPool CAN'T delegate to $ClassicResourceType $ClassicServer"

	# Check the list of SPNs Coresight can delegate to for a match.
	If ($ClassicDelegationList -match $ClassicShortSPN -and $ClassicDelegationList -match $ClassicLongSPN) { 
		$global:strClassicDelegation += $msgCanDelegateToClassic
	} 
	Else { 
		$global:strClassicDelegation += $msgCanNotDelegateToClassic
	}

}

Function Check-KernelModeAuth
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("CustomAppPool")]
		[boolean]
		$blnCustomAppPoolAccount,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("UseAppPoolCreds")]
		[boolean]
		$blnUAppPoolPwdKerbTicketDecrypt,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("UseKernelModeAuth")]
		[boolean]
		$blnUseKernelModeAuth,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

		If ($blnUseKernelModeAuth -ne $True) {

			If ($blnCustomAppPoolAccount -eq $True) {
				$global:strRecommendations += "`n ENABLE Kernel-mode Authentication and set UseAppPoolCredentials property to TRUE. 
				`n For more information, see http://aka.ms/kcdpaper. `n "
			}

			Else {
				$global:strRecommendations += "`n ENABLE Kernel-mode Authentication. 
				`n For more information, see http://aka.ms/kcdpaper. `n "
			}
		}

		Else {
			If ($blnCustomAppPoolAccount -eq $True -and $blnUAppPoolPwdKerbTicketDecrypt -eq $false){
			$global:strIssues += "`n Kerberos Authentication will fail. `n Kernel-mode Authentication is enabled AND a Custom Account is running Coresight AppPools, BUT UseAppPoolCredentials property is set to FALSE. `n Change it to TRUE. For more information, see http://aka.ms/kcdpaper. `n "
			$global:issueCount += 1
			}

		}
}

Function Get-CoresightAppPoolNetworkIdentityName
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("AppPoolIDType")]
		[string]
		$AppPoolIdentityType,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("AppPoolUserString")]
		[string]
		$AppPoolUsernameValue,
		[alias("ServerName")]
		[string]
		$IISserverName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	$CSUserGMSA = $AppPoolUsernameValue | Out-String

    If ($AppPoolIdentityType -ne "NetworkService" -and $AppPoolIdentityType -ne "ApplicationPoolIdentity" -and $AppPoolIdentityType -ne "LocalSystem")
    { 
        $global:blnCustomAccount = $true

		$global:CSAppPoolIdentity = $AppPoolUsernameValue
        
        If ($CSUserGMSA.contains('$')) { $global:blngMSA = $True } 
		Else {   
			$global:blngMSA = $false 
            $global:strRecommendations += "`n Use a Group Managed Service Account. For more information, see - https://blogs.technet.microsoft.com/askpfeplat/2012/12/16/windows-server-2012-group-managed-service-accounts. `n "
        }

		$CSAppPoolPosition = $AppPoolUsernameValue.IndexOf("\")
		$global:CoresightAppPoolAccount = $AppPoolUsernameValue.Substring($CSAppPoolPosition+1)
		$global:CoresightAppPoolAccount = $global:CoresightAppPoolAccount.TrimEnd('$')
		$global:CoresightAppPoolAccount = $global:CoresightAppPoolAccount.ToLower()
		
		$global:CoresightAppPoolAccountPretty = $AppPoolUsernameValue
    }
    Else
    {
            $global:blnCustomAccount = $false
            $global:blngMSA = $false
            $global:strRecommendations += "`n Use a Group Managed Service Account. For more information, see - https://blogs.technet.microsoft.com/askpfeplat/2012/12/16/windows-server-2012-group-managed-service-accounts. `n "
			
			$global:CSAppPoolIdentity = $AppPoolIdentityType
			$global:CoresightAppPoolAccount = $IISserverName.ToLower()
			
			$global:CoresightAppPoolAccountPretty =$AppPoolIdentityType
    }

}

Function Check-ServicePrincipalName
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("chh")]
		[boolean]
		$HostA,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("SPN1")]
		[string]
		$SPNstring1,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("SPN2")]
		[string]
		$SPNstring2,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("TargetAccountName")]
		[string]
		$strSPNtargetAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("TargetDomain")]
		[string]
		$strSPNtargetDomain="",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	
		If ($strSPNtargetDomain -eq "") {	$SPNCheck = $(setspn -q $SPNstring1).ToLower() | Out-String }
		Else { $SPNCheck = $(setspn -t $strSPNtargetDomain -q $SPNstring1).ToLower() | Out-String }
		If ($HostA) {

			If ($SPNCheck -match $SPNstring1 -and $SPNCheck -match $strSPNtargetAccount) { 
				$global:strSPNs = "Service Principal Name $SPNstring1 exists and is assigned to the service identity: $global:CoresightAppPoolAccountPretty." 			
			}
			Else { 
				$global:strSPNs = "Required Service Principal Name could not be found. See ISSUES section for further details."
				$global:strIssues += "Kerberos authentication will fail. Please make sure $SPNstring1 Service Principal Name is assigned to the correct service identity: $global:CoresightAppPoolAccountPretty.
				`n For more information, see https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-68329569-D75C-406D-AE2D-9ED512E74D46 "
				$global:issueCount += 1			
			}
		}

		Else {
			If ($SPNCheck -match $SPNstring1 -and $SPNCheck -match $SPNstring2 -and $SPNCheck -match $strSPNtargetAccount) { 
				$global:strSPNs = "Service Principal Names $SPNstring1 and $SPNstring2 exist and are assigned to the service identity: $global:CoresightAppPoolAccountPretty."   
			}
			Else { 
				$global:strSPNs = "Required Service Principal Names could not be found. See ISSUES section for further details."
				$global:strIssues += "Kerberos authentication will fail. Please make sure $SPNstring1 and $SPNstring2 Service Principal Names are assigned to the correct service identity: $global:CoresightAppPoolAccountPretty.
				`n For more information, see https://livelibrary.osisoft.com/LiveLibrary/content/en/coresight-v8/GUID-68329569-D75C-406D-AE2D-9ED512E74D46 "
				$global:issueCount += 1
				
			}
		}
		
}

Function Initialize-CoresightKerberosConfigurationTest
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("cn")]
		[string] $ComputerName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("kc")]
		[ValidateSet('None','Classic','ResourceBased','Menu')]
		[string] $KerberosCheck,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	# Initialize Global Paths if not set
	if($null -eq (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value -or $null -eq (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value){ SetFolders }
	
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
				$msgTemplate = @"
	The server: {0} has a problem with WinRM communication. 
	This issue will occur if there is an HTTP/hostname or HTTP/fqdn SPN assigned to a 
	custom account.  In this situation the scripts may need to be run locally.  
	For more information, see - https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS).
"@
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

	# Resolve KerberosCheck selection
	if($KerberosCheck -eq 'Menu')
	{
		$title = "PI DOG"
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
			'ResourceBased' {$result = 2}
		}
	}

	return $result
}

# ........................................................................
# Exported Functions
# ........................................................................
Function Test-CoresightKerberosConfiguration {
<#  
.SYNOPSIS
Designed to check Coresight configuration to ensure Kerberos authentication and delegation
are configured correctly.  

.DESCRIPTION
Dubbed 'PI Dog' after Kerberos, the three-headed guardian of Hades. This utility is designed to
examine the configuration of a PI Coresight web application related to Kerberos delegation and 
provide actionable information if any issues or deviation from best practices are detected.
	
PI Dog has best support when run locally due to complications with WS-Man, SPN resolution or 
cross domain complications.  If there is an HTTP/hostname or HTTP/fqdn SPN for the web server
assigned to a custom account, the scripts may need to be run locally.  For more information, 
see - https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS).

The syntax is...				 
Test-CoresightKerberosConfiguration [[-ComputerName | -cn] <string>]

Import the PISYSAUDIT module to make this function available.

.PARAMETER cn
The computer hosting the target PI Coresight web application.
.PARAMETER kc
The type of kerberos delegation configuration check to perform.  Supported values
are None, Classic, ResourceBased and Menu (select interactively).
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
		[string] $KerberosCheck = "Menu",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0		
	)	

	$fn = GetFunctionName
	
	$result = Initialize-CoresightKerberosConfigurationTest -cn $ComputerName -kc $KerberosCheck

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
			$ADMtemp = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -ne 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbkcd = $false
        }

		# Basic IIS checks + resource based Kerberos constrained delegation check
        2 {"Resource-Based Kerberos Delegation configuration will be checked."
			$ADMtemp = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -ne 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbkcd = $true
        }
    }

# If needed, give user option to install 'Remote Active Directory Administration' PS Module.
If ($ADMtemp) {
	$localOS = (Get-CimInstance Win32_OperatingSystem).Caption
	If($localOS -like "*Windows 10*" -or $localOS -like "*Windows 8*" -or $localOS -like "*Windows 7*"){
		$messageRSAT = @"
		'Remote Active Directory Administration' Module is not installed.  This module is required on the 
		machine running Test-CoresightKerberosConfiguration.  A client operating system was detected, so 
		ServerManager is not available; the tool must be downloaded and installed.  
		For more information, see - https://support.microsoft.com/en-us/kb/2693643

		'Remote Active Directory Administration' is required to check Kerberos Delegation settings. Aborting.
"@
		Write-Output $messageRSAT
		break
	}
	Else
	{
		$titleRSAT = "RSAT-AD-PowerShell required"
		$messageRSAT = @"
	'Remote Active Directory Administration' Module is required on the machine running Test-CoresightKerberosConfiguration.
	Installing this module does not require a reboot.  If it is desired to uninstall the module afterward, a reboot will be
	required to complete the removal.
"@
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
}

	# Initialize variables
	$global:strIssues = $null
	$global:issueCount = 0
	$global:strRecommendations = $null
	$global:strClassicDelegation = $null
	$global:RBKCDstring = $null
	$CoresightDelegation = $null
	$RemoteComputerName = $ComputerName
	If($ComputerName -eq ""){$LocalComputer = $true}
	Else{$LocalComputer = $false}

	if(Test-PISysAudit_IISModuleAvailable -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel)
	{
		$msg = 'WebAdministration module loaded successfully.'
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
	}
	else
	{
		Write-Warning 'Unable to load the WebAdministration module on target machine.  Exiting... `nEnsure the Web-Scripting-Tools are installed and you have sufficient privilege.'
		break
	}

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
	$QueryCSAppPoolSvcType = "Get-ItemProperty iis:\apppools\coresightserviceapppool -Name processmodel.identitytype"
	$CSAppPoolSvcType = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QueryCSAppPoolSvcType -DBGLevel $DBGLevel

	# Get CoreSight Admin AppPool Identity Type
	$QueryCSAppPoolAdmType = "Get-ItemProperty iis:\apppools\coresightadminapppool -Name processmodel.identitytype"
	$CSAppPoolAdmType = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QueryCSAppPoolAdmType -DBGLevel $DBGLevel

	# Get the username when a specific user is specified
	if($CSAppPoolSvcType -eq 'SpecificUser'){
		$QuerySvcUser = "Get-ItemProperty iis:\apppools\coresightserviceapppool -Name processmodel.username.value"
		$CSUserSvc = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QuerySvcUser -DBGLevel $DBGLevel
	}
	else { $CSUserSvc = $CSAppPoolSvcType }
	if($CSAppPoolAdmType -eq 'SpecificUser'){
		$QueryAdmUser = "Get-ItemProperty iis:\apppools\coresightadminapppool -Name processmodel.username.value"
		$CSUserAdm = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $QueryAdmUser -DBGLevel $DBGLevel
	}
	else { $CSUserAdm = $CSAppPoolSvcType }
	
    # Get Windows Authentication Property
    $blnWindowsAuthQueryTemplate = "Get-WebConfigurationProperty -PSPath `"{0}`" -Filter '/system.webServer/security/authentication/windowsAuthentication' -name enabled | select -expand Value"
    $blnWindowsAuthQuery = [string]::Format($blnWindowsAuthQueryTemplate, $csAppPSPath)
    $blnWindowsAuth = Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $blnWindowsAuthQuery -DBGLevel $DBGLevel
    # Windows Authentication must be enabled - if it isn't, exit.
    if (!$blnWindowsAuth) { 
    Write-Warning "Windows Authentication must be enabled! Aborting."
    break }

    # Get Windows Authentication Providers
    $authProvidersCollectionQueryTemplate = "Get-WebConfigurationProperty -PSPath `"{0}`" -Filter '/system.webServer/security/authentication/windowsAuthentication/providers' -Name *"
	$authProvidersCollectionQuery = [string]::Format($authProvidersCollectionQueryTemplate, $csAppPSPath)
	$authProviders = $(Get-PISysAudit_IISproperties -lc $LocalComputer -rcn $RemoteComputerName -qry $authProvidersCollectionQuery -DBGLevel $DBGLevel).Collection
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
    $CSWebServerName = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" "ComputerName" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
    $CSWebServerDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
    $CSWebServerFQDN = $CSWebServerName + "." + $CSWebServerDomain 

		# GET CORESIGHT APPPOOL IDENTITY
		Get-CoresightAppPoolNetworkIdentityName -AppPoolIDType $CSAppPoolSvcType -AppPoolUserString $CSUserSvc -ServerName $CSWebServerName


		# KERNEL-MODE AUTHENTICATION CHECK
		Check-KernelModeAuth -CustomAppPool $global:blnCustomAccount -UseAppPoolCreds $blnUseAppPoolCredentials -UseKernelModeAuth $blnKernelMode -DBGLevel $DBGLevel      
	

		# CHECK BINDINGS, CHECK IF CUSTOM HOST HEADER IS USED

			$blnCustomHeader = $false
			$HostA = $False 

			$BindingsToString = $($CSWebBindings) | Out-String
			$matches = [regex]::Matches($BindingsToString, ':{1}\d+:{1}(\S+)\s') 
						foreach ($match in $matches) { 
							$CSheader = $match.Groups[1].Captures[0].Value 
								If ($CSheader) { 
									$blnCustomHeader = $true
									$CScustomHeader = $CSheader
								break 
								}
						}
			
			If ($blnCustomHeader -eq $True) {								
				$AliasTypeCheck = Resolve-DnsName $CScustomHeader | Select -ExpandProperty Type

				If ($AliasTypeCheck -match "CNAME") { 
					$HostA = $False 
					$CScustomHeaderType = "CNAME DNS Alias"
				}
				Else {
					$HostA = $True
					$CScustomHeaderType = "HOST (A) DNS Record"
				}
			}

		# CORESIGHT SERVICE PRINCIPAL NAMES CHECK
				$CSUserSvcDomain = Get-ServiceLogonAccountDomain -ServiceAccount $CSUserSvc -DBGLevel $DBGLevel
				If ($global:blnCustomAccount -eq $true -and $HostA -eq $true) {
					$SPNone = ("http/" + $CScustomHeader).ToLower()
					Check-ServicePrincipalName -chh $HostA -spn1 $SPNone -TargetAccountName $global:CoresightAppPoolAccount -TargetDomain $CSUserSvcDomain
				}

				ElseIf ($global:blnCustomAccount -eq $true -and $HostA -eq $false) {
					$SPNone = ("http/" + $CSWebServerName).ToLower()
					$SPNtwo = ("http/" + $CSWebServerFQDN).ToLower()
					Check-ServicePrincipalName -chh $HostA -spn1 $SPNone -spn2 $SPNtwo -TargetAccountName $global:CoresightAppPoolAccount -TargetDomain $CSUserSvcDomain
				}
				Else {
					$SPNone = ("host/" + $CSWebServerName).ToLower()
					$SPNtwo = ("host/" + $CSWebServerFQDN).ToLower()
					Check-ServicePrincipalName -chh $HostA -spn1 $SPNone -spn2 $SPNtwo -TargetAccountName $global:CoresightAppPoolAccount -TargetDomain $CSUserSvcDomain
				}

		# KERBEROS DELEGATION CHECK CONFIRMED
		If ($blnDelegationCheckConfirmed) {
				   
			# Get PI and AF Servers from the web server KST
			$AFServers = Get-KnownServers -lc $LocalComputer -rcn $RemoteComputerName -st AFServer 
			$PIServers = Get-KnownServers -lc $LocalComputer -rcn $RemoteComputerName -st PIServer
			
				# RESOURCE BASED KERBEROS DELEGATION
				If ($rbkcd) {
				
							foreach ($AFServerTemp in $AFServers) { 
								$AccType = 0
								$AFServer = $AFServerTemp.Groups[1].Captures[0].Value
						
									$msgTemplate = "Processing RBCD check for AF Server {0}"
									$msg = [string]::Format($msgTemplate, $AFServer)
									Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

									$AFSvcAccount = Get-PISysAudit_ServiceLogOnAccount "afservice" -lc $false -rcn $AFServer -ErrorAction SilentlyContinue
									
										If ($AFSvcAccount -ne $null ) { 
										$AFSvcAccountDomain = Get-ServiceLogonAccountDomain -sa $AFSvcAccount
										$AccType = Get-ServiceLogonAccountType -sa $AFSvcAccount -sad $AFSvcAccountDomain -cn $AFServer -DBGLevel $DBGLevel
							
											if($AccType -eq 0)
											{
												Write-Output "Unable to locate type of ADObject $AFSvcAccount."
												continue
											}
							
											Check-ResourceBasedConstrainedDelegationPrincipals -sa $AFSvcAccount -sad $AFSvcAccountDomain -sat $AccType -api $global:CoresightAppPoolAccount -cn $AFServer -rt "AF Server" -DBGLevel $DBGLevel
										}
							
										Else { 
										$global:RBKCDstring += "`n Could not get the service account running AF Server. Please make sure AF Server $AFServer is configured for PSRemoting.
										https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS) `n "
										}

								}

								foreach ( $PIServer in $PIServers ) { 
									$AccType = 0
									$PISvcAccount = Get-PISysAudit_ServiceLogOnAccount "pinetmgr" -lc $false -rcn $PIServer -ErrorAction SilentlyContinue
									
									$msgTemplate = "Processing RBCD check for PI Server {0}"
									$msg = [string]::Format($msgTemplate, $PIServer)
									Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

										If ( $PISvcAccount -ne $null ) 
										{ 
											$PISvcAccountDomain = Get-ServiceLogonAccountDomain -sa $PISvcAccount -DBGLevel $DBGLevel
											$AccType = Get-ServiceLogonAccountType -sa $PISvcAccount -sad $PISvcAccountDomain -cn $PIServer -DBGLevel $DBGLevel
											if($AccType -eq 0)
											{
												Write-Output "Unable to locate type of ADObject $PISvcAccount."
												continue
											}
											Check-ResourceBasedConstrainedDelegationPrincipals -sa $PISvcAccount -sad $PISvcAccountDomain -sat $AccType -api $global:CoresightAppPoolAccount -cn $PIServer -rt "PI Server" -DBGLevel $DBGLevel
										}
										Else 
										{ 
											$global:RBKCDstring += "`n Could not get the service account running PI Server. Please make sure PI Server $PIServer is configured for PSRemoting.
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

						If ($global:blnCustomAccount -eq $True) {
							If ($global:blngMSA -eq $True) { $ClassicAccType = 3 }
							Else { $ClassicAccType = 1 }
						}
						Else {	$ClassicAccType = 2 }
					
					# Initializing variables needed to construct an SPN
					$dot = '.'
					$PISPNClass = "piserver/"
					$AFSPNClass = "afserver/"

					foreach ($PIServer in $PIServers) {
							
							# Debug option
							$msgTemplate = "Processing Classic Delegation check for PI Server {0}"
							$msg = [string]::Format($msgTemplate, $PIServer)
							Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

							# PI Server is specified as FQDN
							If ($PIServer -match [regex]::Escape($dot)) { 
							$fqdnPI = $PIServer.ToLower() 
							$pos = $fqdnPI.IndexOf(".")
							$shortPI = $fqdnPI.Substring(0, $pos)
							}

							# PI Server is specified as short host name
         					Else { 
							$shortPI = $PIServer.ToLower() 
							$fqdnPI = ($PIServer.ToLower() + "." + $CSWebServerDomain.ToLower()).ToString()
							}
						
							# Construct SPNs
							$shortPISPN = ($PISPNClass + $shortPI).ToString()
							$longPISPN = ($PISPNClass + $fqdnPI).ToString()

					# Check if the SPN is on the list the Coresight AppPool can delegate to
					Check-ClassicDelegation -sspn $shortPISPN -lspn $longPISPN -cap $global:CoresightAppPoolAccount -crt "PI Data Server" -cse $PIServer -cat $ClassicAccType
					}

					
					foreach ($AFServerTemp in $AFServers) {
							$AFServer = $AFServerTemp.Groups[1].Captures[0].Value

							# Debug option
							$msgTemplate = "Processing Classic Delegation check for AF Server {0}"
							$msg = [string]::Format($msgTemplate, $AFServer)
							Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

							If ($AFServer -match [regex]::Escape($dot)) { 
					
							# AF Server is specified as FQDN
							$fqdnAF = $AFServer.ToLower() 
							$pos = $fqdnAF.IndexOf(".")
							$shortAF = $fqdnAF.Substring(0, $pos)
							}
							# AF Server is specified as short host name
         					Else { 
							$shortAF = $AFServer.ToLower() 
							$fqdnAF = ($AFServer.ToLower() + "." + $CSWebServerDomain.ToLower()).ToString()
							}
						
							# Construct SPNs
							$shortAFSPN = ($AFSPNClass + $shortAF).ToString()
							$longAFSPN = ($AFSPNClass + $fqdnAF).ToString()

					# Check if the SPN is on the list the Coresight AppPool can delegate to
					Check-ClassicDelegation -sspn $shortAFSPN -lspn $longAFSPN -cap $global:CoresightAppPoolAccount -crt "AF Server" -cse $AFServer -cat $ClassicAccType
					}
								
				$CoresightDelegation = $global:strClassicDelegation
				}


				# BACK-END SERVICES SERVICE PRINCIPAL NAME CHECK
				foreach ($AFServerBEC in $AFServers) {
					$AFServer = $AFServerBEC.Groups[1].Captures[0].Value
					$serviceType = "afserver"
					$serviceName = "afservice"
					$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $false -rcn $AFServer -dbgl $DBGLevel
					If ($result -ne $null) {
						If ($result) { $strBackEndSPNS += "`n Service Principal Names for AF Server $AFServer are set up correctly." }
						Else { $strBackEndSPNS += "`n *Service Principal Names for AF Server $AFServer are NOT set up correctly." }
					}
					Else { 
					$strBackEndSPNS += "`n Could not get the service account running AF Server $AFServer. Make sure it is configured for PSRemoting.
					https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS) `n "
					}
				}

				foreach ($PIServerBEC in $PIServers) {
					$serviceType = "piserver"
					$serviceName = "pinetmgr"
					$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $false -rcn $PIServerBEC -dbgl $DBGLevel
					If ($result -ne $null) {
						If ($result) { $strBackEndSPNS += "`n Service Principal Names for PI Server $PIServerBEC are set up correctly." }
						Else { $strBackEndSPNS += "`n *Service Principal Names for PI Server $PIServerBEC are NOT set up correctly." }
					}
					Else { 
					$strBackEndSPNS += "`n Could not get the service account running PI Server $PIServerBEC. Make sure it is configured for PSRemoting.
					https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS) `n "
					}
				}
			 
			}


#### Summary
$exportPath = (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value
$LogFile = $exportPath + "\CoresightKerberosConfig.log"
##### Compose Authentication section 
If($blnWindowsAuth)
{
	$strCoresightAuthenticationSection=@"
		Is Windows Authentication Enabled: $blnWindowsAuth
        Windows Authentication Providers: $strProviders
        Kernel-mode Authentication Enabled: $blnKernelMode
        UseAppPoolCredentials property: $blnUseAppPoolCredentials
"@
}
Else
{
	$strCoresightAuthenticationSection=@"
		Is Windows Authentication Enabled: $blnWindowsAuth
"@
}
##### Compose Customer Header section 
If($blnCustomHeader)
{
	$strCoresightWebSiteBindingsSection=@"
        Is Custom Host Header used: $blnCustomHeader
		Custom Host Header name: $CScustomHeader
		Custom Host Header type: $CScustomHeaderType
"@
}
Else
{
	$strCoresightWebSiteBindingsSection=@"
        Is Custom Host Header used: $blnCustomHeader
"@
}
##### Compose Kerberos Check section 
If($blnDelegationCheckConfirmed)
{
	$strCoresightKerberosDelegationsSection=@"
		Coresight - Service Principal Names: $global:strSPNs
		`n
		PI/AF - Service Principal Names: $strBackEndSPNS
		`n
		Coresight AppPool - Kerberos Delegation: $CoresightDelegation
		`n
"@
}
Else
{
	$strCoresightKerberosDelegationsSection=@"
        Coresight - Service Principal Names: $global:strSPNs
		`n
"@
}
####
$strSummaryReport = @"
    Coresight Authentication Settings:
$strCoresightAuthenticationSection
        `n
    Coresight Web Site Bindings:
$strCoresightWebSiteBindingsSection
        `n
    Coresight AppPool Identity: $global:CSAppPoolIdentity
        Group Managed Service Account used: $global:blngMSA
        `n
$strCoresightKerberosDelegationsSection
		`n
	RECOMMENDATIONS: $global:strRecommendations
        `n
	NUMBER OF ISSUES FOUND: $global:issueCount
        `n
	ISSUES - DETAILS: $global:strIssues 
        `n
	Report recorded to the log file: $LogFile 
"@

Write-Output $strSummaryReport
$strSummaryReport | Out-File $LogFile
}

Export-ModuleMember -Function Test-CoresightKerberosConfiguration
Set-Alias -Name Unleash-PI_Dog -Value Test-CoresightKerberosConfiguration -Description “Sniff out Kerberos issues.”
Export-ModuleMember -Alias Unleash-PI_Dog