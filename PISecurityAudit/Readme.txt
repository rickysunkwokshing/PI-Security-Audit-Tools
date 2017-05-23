################
# Requirements #
################

PowerShell version 3.0 or later is required.
If targeting a remote machine with the scripts then PS-Remoting must be enabled on the target machine.  You can test whether or not PS-Remoting is enabled with the command below, where <TargetComputer> is the machine that the scripts will be run against.  We do not recommend enabling PS-Remoting to run this tool if it is not already enabled.
	Test-WSMan -authentication default -ComputerName <TargetComputer>

Modules: 
WebAdministration Module: the IIS Management PowerShell module must be installed on the target web server to read IIS configuration data when performing a PI Coresight role audit.
OSIsoft.PowerShell: PowerShell Tools for the PI System are required for the PI Data Archive and PI AF Server checks.

Permissions:
PI Data Archive - Read access to PIDBSEC, PIMAPPING, PITRUST, PIUSER and PITUNING in database security.
PI AF Server - Process must be run as administrator to access AFDiag locally.
PI Coresight - Process must be run as administrator to access IIS Configuration data.
SQL Server - Login with the public server role.

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

###############################
# Accessing the built in help #
###############################
Read the help documentation on the New-PISystemAuditReport cmdlet by typing the following:  
    Get-Help New-PISystemAuditReport

To view the conceptual help, run the command below:  
    Get-Help about_PISYSAUDIT

#############
# Resources #
#############

PI Security Audit Tools Repository
https://github.com/osisoft/PI-Security-Audit-Tools

PI Security Audit Tools Repository Wiki
https://github.com/osisoft/PI-Security-Audit-Tools/wiki

PI Square Security Forum
https://pisquare.osisoft.com/groups/security