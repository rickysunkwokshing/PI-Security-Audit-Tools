# PI-System-Audit-Tools

## Contents
This project is a framework to baseline the security configuration of your PI System. This tool framework is built as a PowerShell module containing cmdlets to perform different calls to collect the data from the security settings of different requested PI System components.
  
A series of PowerShell script files (*.psm1) form a single module named PI System Audit Module (or PISysAudit Module) once loaded. You will find one core script containing the collection logic and four library scripts containing the validation logic for different topics such as best practices to harden the machine, PI Server, etc. The module exposes several cmdlets either used for the internal logic or the external interface with the end-user.

The PI System Audit Module (PISysAudit) requires PowerShell version 2 and later, it can be executed locally or remotely and make use of existing command line utilities to perform many tasks. This allows being compatible with many versions of the PI System.  

The current version of the PISysAudit module implements 16 validations covering machine (AU1XXXX), PI Server (AU2XXXX), PI AF Server (AU3XXXX) and SQL Server (AU4XXXX) best practices with the PI System.  
 
Validations:	             
AU10001 -	Domain Membership Check 
AU10002	- OS SKU  
AU10003	- Validate if Windows firewall is enabled  	
AU20001	- PI Data Archive Table Security	
AU20002	- PI Admin Trusts Disabled	 
AU20003	- PI Data Archive Subsystem Version  	
AU20004	- Edit Days  
AU20005	- Auto Trust Configuration	 
AU20006	- Expensive Query Protection  	
AU30001	- PI AF Server Service Account  
AU30002	- Impersonation mode for AF Data Sets  
AU30003	- PI AF Server Service Access  
AU40001	- SQL Server xp_CmdShell	 
AU40002	- SQL Server Adhoc Queries	 
AU40003	- SQL Server DB Mail XPs	 
AU40004	- SQL Server OLE Automation Procedures	 

## Getting Started

SETUP INSTRUCTIONS
The PISysAudit module does not require installation; you only need to decompress the package. You will need to import the module from the extracted location in order to use it. The file structure is the following:  
  * bin = Contains command line utilities or PS scripts needed by the PS module
  * bin\pisysaudit = Contains the PS module definition
  * export = Contains the generated reports
  * pwd = Contains saved password files using strong encryption
  
For example, if you have decompressed the package inside your user folder (C:\users\<user>\documents\pisysaudit v1.0.0.8), you need to import the module the following:
 
  Import-Module "C:\users\<user>\documents\pisysaudit v1.0.0.8\bin\pisysaudit"

USAGE EXAMPLES
The audit is launched with the New-PISysAuditReport cmdlet (or you can use the alias: piaudit). Two examples are provided below to help you.
 
Example 1
Use the command below to launch an audit with all PI Server, AF Server and SQL Server components installed locally. It makes use of all default parameters to perform the audit.
    piaudit

Example 2
Use the commands below to launch the audit with two PI Servers, one AF Server and one SQL Server components installed on different machines than the one used to launch the script.  
    $cpt = piauditparams $null "Computer1" "PIServer"  
    $cpt = piauditparams $cpt "Computer2" "PIServer"  
    $cpt = piauditparams $cpt "Computer3" "PIAFServer"  
    $cpt = piauditparams $cpt "Computer4" "SQLServer" -InstanceName "sqlexpress"  
    piaudit -cpt $cpt  

You get more details by invoking the help with the Get-Help cmdlet like the following:  
    Get-Help piaudit  
You can also find several examples of commands and syntaxes for this module within examples.ps1 file.  


## Licensing

Copyright 2016 OSIsoft, LLC.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   
Please see the file named [LICENSE.md](LICENSE.md).