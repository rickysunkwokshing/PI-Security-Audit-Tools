################
# Requirements #
################

PowerShell version 3.0 or later is required to run this tool.
If targeting a remote machine with the scripts then PS-Remoting must be enabled on the target machine.  You can test whether or not PS-Remoting is enabled with the command below, where <TargetComputer> is the machine that the scripts will be run against.  We do not recommend enabling PS-Remoting to run this tool if it is not already enabled.
	Test-WSMan -authentication default -ComputerName <TargetComputer>

Modules: 
The following role audit checks have specific module requirements below.
PI Vision: 
+WebAdministration (IIS Management) - must be installed on the target web server to read IIS configuration data when performing a PI Vision role audit.
PI AF Server: 
+OSIsoft.PowerShell (PowerShell Tools for the PI System) - must be installed on machine running the PI Security Audit Tools script
PI Data Archive: 
+OSIsoft.PowerShell (PowerShell Tools for the PI System) - must be installed on machine running the PI Security Audit Tools script
SQL Server: 
+SQLPS - must be installed on machine running the PI Security Audit Tools script.  To install the SQLPS module with minimal other components on Windows 8/Server 2012 or later, go to https://www.microsoft.com/en-us/download/details.aspx?id=52676 and select ENU\x64\PowerShellTools.msi, ENU\x64\SharedManagementObjects.msi and ENU\x64\SQLSysClrTypes.msi.

Permissions:
PI Data Archive - Read access to PIDBSEC, PIMAPPING, PIMSGSS, PITRUST, PIUSER and PITUNING in database security.
PI AF Server - Process must be run as administrator to access AFDiag locally.
PI Vision - Process must be run as administrator to access IIS Configuration data.
SQL Server - The user executing the scripts must have a Login with the public server role.

#############################
# Preparing to run the tool #
#############################

Open a PowerShell session (64 bit). Right-click on the PowerShell shortcut on the task bar and choose "Run As Administrator".  

Check your Execution Policy (https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.security/set-executionpolicy) for PowerShell.  
    Get-ExecutionPolicy -Scope Process

If the result of the previous command is "Restricted" you will need to update the policy to run the script.  If you are using the released version from this repository or the OSIsoft tech support site, then they are signed and you can set the value to "AllSigned" with the command below.  If you are testing a development copy of the scripts, then you will need to replace "AllSigned" with a more permissive policy, such as "Unrestricted".  
    Set-ExecutionPolicy AllSigned -Scope Process

Change directory to the folder containing the module manifest file (.psd1) with the cd command like the one below.  Replace the "D:\ExtractedToPath\" portion with the path you extracted the PI Security Audit Tools to.  
    CD D:\ExtractedToPath\PISecurityAudit

Import the PI System Audit Module by typing the command below.  
    Import-Module .\PISYSAUDIT.psd1

To validate that the module has been successfully loaded you can test with the Get-Module cmdlet as shown below.  If successful, you will see the ModuleType, Name and ExportedCommands.  
    Get-Module PISYSAUDIT  

###############################
# Accessing the built in help #
###############################
To read the help documentation on the New-PISystemAuditReport cmdlet, type the following:  
    Get-Help New-PISystemAuditReport

Similarly, retrieve help for the Kerberos Configuration Utility or the Security Configuration Export Utility
	Get-Help Test-KerberosConfiguration
	Get-Help Export-PISecConfig

To view the conceptual help, run the command below:  
    Get-Help about_PISYSAUDIT

####################
# Running the tool #
####################

Enter the following instruction to add a PI Data Archive component to the audit (substitute in the name of your machine for PIOmniBox):  
    $cpt = piauditparams $null "piomnibox" "pidataarchive"  

If you have other components to add, you can add them to the same object.  For example, the command below also adds a PI AF Server component.  
    $cpt = piauditparams $cpt "piomnibox" "piafserver"

Finally, when you are done adding components, launch the audit with the piaudit command.  
    piaudit -cpt $cpt

Open the generated *.html file from the Export folder in your favorite browser and examine the results.  

#############################
# Running a batch of audits #
#############################

A more convenient way to audit several components at once may be to use the computer parameters file 
option that uses a CSV file with parameters.
	piaudit -cpf "D:\PathToYourFile\Servers.csv"

Sample contents for CSV file are below.
NOTE: headings must be included.
	ComputerName,PISystemComponentType,InstanceName,IntegratedSecurity,SQLServerUserID,PasswordFile
	mySQL1,sql,sqlexpress,false,myTestUser,
	myPI1,pidataarchive,,,,
	myPI1,piaf,,,,

If no SQL Servers are included, the file can be simplified to two columns as shown below
	ComputerName,PISystemComponentType
	myPI1,piaf
	myPI1,pidataarchive
	myPI2,pivision

#############
# Resources #
#############

PI Security Audit Tools Repository
https://github.com/osisoft/PI-Security-Audit-Tools

PI Security Audit Tools Repository Wiki
https://github.com/osisoft/PI-Security-Audit-Tools/wiki

PI Square Security Forum
https://pisquare.osisoft.com/groups/security