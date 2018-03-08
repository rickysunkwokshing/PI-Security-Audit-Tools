# ************************************************************************
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
# ************************************************************************

<#
.SYNOPSIS

This example configuration covers deterministic configuration items that are
validated during the PI Security Audit Tools validation checks for the PI 
Data Archive.

.DESCRIPTION
    
While some validation checks are more involved, there are many which can be 
corrected with a simple there are many checks which cover

.PARAMETER DaysToAllowEdits

Defines the number of days to allow edits to archive and snapshot data.  Any 
non-zero value is accepted, though the value should be chosen to reflect the 
practical reality of your environment.

.PARAMETER MaxQueryExecutionSeconds

Defines the maximum time that a query will be allowed to run.  Accepted values
are between 60 and 300 seconds.

.PARAMETER AutoTrustConfig

Defines trusts that are automatically created by the PI Data Archive.  Accepted
values include:
 0 - No trusts created
 1 - Loopback trust created for 127.0.0.1

.PARAMETER PIFirewallHostmasks

The PI Firewall provides an additional layer of protection by only allowing 
connections to the PI Data Archive from approved sources. 

.PARAMETER AuthenticationPolicy

Similar to the 'Security Slider' in PI SMT, this determines the authentication 
protocols available to PI Data Archive clients.  Accepted values:
 3  -  block explicit login (DEFAULT)
 19 -  block PI SDK applications from using trusts
 51 -  block all applications from using trusts

.EXAMPLE 
.\PIDataArchive_AuditBaseline -NodeName "myPI" -DaysToAllowEdit 60 -MaxQueryExecutionSeconds 300 -AutoTrustConfig 0 -PIFirewallHostmasks @('10.10.*.*','10.1.*.*') -AuthenticationPolicy 51

#>
Configuration PIDataArchive_AuditBaseline
{
    param(
        [String] 
        $NodeName = 'localhost',
        
        [Int32] 
        $DaysToAllowEdit = 365,
       
        [ValidateRange(60,300)]
        [Int32] 
        $MaxQueryExecutionSeconds=260,
        
        [ValidateSet('0','1')]
        [Int32] 
        $AutoTrustConfig=0,
        
        [String[]] 
        $PIFirewallHostmasks = @('10.*.*.*','192.168.*.*'),
        
        [ValidateSet('3','19','51')]
        [Int32] 
        $AuthenticationPolicy='3'
         )

    Import-DscResource -ModuleName PISecurityDSC

    Node $NodeName
    {
        # AU20001 - Disable PIWorld
        PIIdentity "AU20001: PIWorld usage"
        {
            Name = 'PIWorld'
            IsEnabled = $false
            AllowUseInTrusts = $false
            Ensure = "Present"
            PIDataArchive = $NodeName
        }
        
        # AU20002 - Restrict use of the piadmin superuser
        PIIdentity 'AU20002: piadmin usage'
        {
            Name = "piadmin"
            AllowUseInTrusts = $false
            AllowUseInMappings = $false
            Ensure = "Present"
            PIDataArchive = $NodeName
        }

        # AU20004 - Specify EditDays
        PITuningParameter 'AU20004: EditDays'
        {
            Name = "EditDays"
            Value = $DaysToAllowEdit
            Ensure = "Present"
            PIDataArchive = $NodeName
        }

        # AU20005 - Auto Trust configuration
        PITuningParameter 'AU20005: AutoTrustConfig'
        {
            Name = "AutoTrustConfig"
            Value = $AutoTrustConfig
            Ensure = "Present"
            PIDataArchive = $NodeName
        }

        # AU20006 - Expensive query protection
        PITuningParameter 'AU20006: Archive_MaxQueryExecutionSec'
        {
            Name = "Archive_MaxQueryExecutionSec"
            Value = $MaxQueryExecutionSeconds
            Ensure = "Present"
            PIDataArchive = $NodeName
        }

        # AU20007 - Explicit Login Disabled
        PITuningParameter 'AU20007: Server_AuthenticationPolicy'
        {
            Name = "Server_AuthenticationPolicy"
            Value = $AuthenticationPolicy
            Ensure = "Present"
            PIDataArchive = $NodeName
        }
        
        # AU20011 - PI Firewall
        $i = 0
        foreach($Hostmask in $PIFirewallHostmasks)
        {
            PIFirewall "AU20011 - PIFirewall Add $i"
            {
                Hostmask = $Hostmask
                Ensure = "Present"
                Value = "Allow" 
                PIDataArchive = $NodeName
            }
            $i++
        }

        PIFirewall "AU20011 - PIFirewall Remove Default"
        {
            Hostmask = '*.*.*.*'
            Ensure = "Absent"
            Value = "Allow" 
            PIDataArchive = $NodeName
            DependsOn = "[PIFirewall]AU20011 - PIFirewall Add 0"
        }
    }
}

PIDataArchive_AuditBaseline