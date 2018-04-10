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

This example configuration covers a basic implementation of Windows Integrated
Security for the PI Data Archive.

.DESCRIPTION
   
This configuration is meant to configure a new install of a PI Data Archive to 
use the standard WIS implementation as documented in the Field Service Technical
Standard in KB01702.

.EXAMPLE 

.\PIDataArchive_BasicWindowsImplementation -NodeName "myPI" -PIAdministratorsADGroup 'mydomain\PI Admins' -PIUsersADGroup 'mydomain\PI Users'

.PARAMETER NodeName

Name of the PI Data Archive server.

.PARAMETER PIAdministratorsADGroup

Windows identity to associate with an administrative role in PI.  Ideally, this 
should be a group.

.PARAMETER PIUsersADGroup

Windows identity to associate with a read only user role in PI.  Ideally, this 
should be a group.

.PARAMETER PIBuffersADGroup

Windows identity to associate with instances of PI Buffer Subsystem.  Ideally, this 
should be a group.

.PARAMETER PIInterfacesADGroup

Windows identity to associate with PI Interfaces.  Ideally, this should be a group.

.PARAMETER PIPointsAnalysisCreatorADGroup

Windows identity to associate with a power user role in PI for those who need to 
create PI Points.  Ideally, this should be a group.

.PARAMETER PIWebAppsADGroup

Windows identity to associate with PI Web Applications such as PI Vision.  Ideally, 
this should be a group.

.PARAMETER PIConnectorRelaysADGroup

Windows identity to associate with PI Connector Relays.  Ideally, 
this should be a group.

.PARAMETER PIDataCollectionManagersADGroup

Windows identity to associate with PI Data Collection Managers.  Ideally, 
this should be a group.

.PARAMETER DSCIdentity

Windows identity that will be used to apply configurations. This will use system
unless a PSCredential is specified in the configuration.

#>
Configuration PIDataArchive_BasicWindowsImplementation
{
    param(
        [String]
        $NodeName = 'localhost',
        
        [String]
        $PIAdministratorsADGroup = 'BUILTIN\Administrators',
        
        [String]
        $PIUsersADGroup = '\Everyone',
        
        [String]
        $PIBuffersADGroup = '',
        
        [String]
        $PIInterfacesADGroup = '',
        
        [String]
        $PIPointsAnalysisCreatorADGroup = '',
        
        [String]
        $PIWebAppsADGroup = '',
		
		[String]
        $PIConnectorRelaysADGroup = '',
        
        [String]
        $PIDataCollectionManagersADGroup = '',
        
        [String]
        $DSCIdentity = 'NT Authority\System'

         )

    Import-DscResource -ModuleName PISecurityDSC

    Node $NodeName
    {
        
        # Create identities for basic WIS roles
        $BasicWISRoles = @(
                            @{Name='PI Buffers';Description='Identity for PI Buffer Subsystem and PI Buffer Server';},
                            @{Name='PI Interfaces';Description='Identity for PI Interfaces';},
                            @{Name='PI Users';Description='Identity for the Read-only users';},
                            @{Name='PI Points&Analysis Creator';Description='Identity for PIACEService, PIAFService and users that can create and edit PI Points';}
                            @{Name='PI Web Apps';Description='Identity for PI Vision, PI WebAPI, and PI WebAPI Crawler';},
							@{Name='PI Connector Relays';Description='Identity for PI Connector Relays';},
							@{Name='PI Data Collection Managers';Description='Identity for PI Data Collection Managers';}
                          )

        Foreach($BasicWISRole in $BasicWISRoles)
        {
            PIIdentity "SetBasicWISRole_$($BasicWISRole.Name)"
            {
                Name = $($BasicWISRole.Name)
                Description = $($BasicWISRole.Description)
                IsEnabled = $true
                CanDelete = $false
                AllowUseInMappings = $true
                AllowUseInTrusts = $true
                Ensure = "Present"
                PIDataArchive = $NodeName
            }
        } 

        # Remove default identities
        $DefaultPIIdentities = @(
                                    'PIOperators',
                                    'PISupervisors',
                                    'PIEngineers',
                                    'pidemo'
                                )
        
        Foreach($DefaultPIIdentity in $DefaultPIIdentities)
        {
            PIIdentity "DisableDefaultIdentity_$DefaultPIIdentity"
            {
                Name = $DefaultPIIdentity
                Ensure = "Absent"
                PIDataArchive = $NodeName
            }
        }

        # Disable default identities
        $DefaultPIIdentities = @(
                                    'PIWorld',
                                    'piusers'
                                )
        
        Foreach($DefaultPIIdentity in $DefaultPIIdentities)
        {
            PIIdentity "DisableDefaultIdentity_$DefaultPIIdentity"
            {
                Name = $DefaultPIIdentity
                IsEnabled = $false
                AllowUseInTrusts = $false
                Ensure = "Present"
                PIDataArchive = $NodeName
            }
        }
        
        # Set PI Mappings 
        $DesiredMappings = @(
                                
                                @{Name=$PIAdministratorsADGroup;Identity='piadmins'},
                                @{Name=$PIBuffersADGroup;Identity='PI Buffers'},
                                @{Name=$PIInterfacesADGroup;Identity='PI Interfaces'},
                                @{Name=$PIPointsAnalysisCreatorADGroup;Identity='PI Points&Analysis Creator'},
                                @{Name=$PIUsersADGroup;Identity='PI Users'},
                                @{Name=$PIWebAppsADGroup;Identity='PI Web Apps'},
								@{Name=$PIConnectorRelaysADGroup;Identity='PI Connector Relays'},
								@{Name=$PIDataCollectionManagersADGroup;Identity='PI Data Collection Managers'}
                                @{Name=$DSCIdentity;Identity='piadmins'}
                            )

        Foreach($DesiredMapping in $DesiredMappings)
        {
            if($null -ne $DesiredMapping.Name -and '' -ne $DesiredMapping.Name)
            {
                PIMapping "SetMapping_$($DesiredMapping.Name)"
                {
                    Name = $DesiredMapping.Name
                    PrincipalName = $DesiredMapping.Name
                    Identity = $DesiredMapping.Identity
                    Enabled = $true
                    Ensure = "Present"
                    PIDataArchive = $NodeName
                }
            }
        }
        
        # Set PI Database Security Rules
        $DatabaseSecurityRules = @(
                                    @{Name='PIAFLINK';Security='piadmins: A(r,w)'},
                                    @{Name='PIARCADMIN';Security='piadmins: A(r,w)'},
                                    @{Name='PIARCDATA';Security='piadmins: A(r,w)'},
                                    @{Name='PIAUDIT';Security='piadmins: A(r,w)'},
                                    @{Name='PIBACKUP';Security='piadmins: A(r,w)'}, 
                                    @{Name='PIBatch';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    # PIBACTHLEGACY applies to the old batch subsystem which predates the PI Batch Database.
                                    # Unless the pibatch service is running, and there is a need to keep it running, this
                                    # entry can be safely ignored. 
                                    # @{Name='PIBATCHLEGACY';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    @{Name='PICampaign';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    @{Name='PIDBSEC';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Data Collection Managers: A(r) | PI Users: A(r) | PI Web Apps: A(r)'},
                                    @{Name='PIDS';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Connector Relays: A(r,w) | PI Data Collection Managers: A(r) | PI Users: A(r) | PI Points&Analysis Creator: A(r,w)'},
                                    @{Name='PIHeadingSets';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    @{Name='PIMAPPING';Security='piadmins: A(r,w) | PI Web Apps: A(r)'},
                                    @{Name='PIModules';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    @{Name='PIMSGSS';Security='piadmins: A(r,w) | PIWorld: A(r,w) | PI Users: A(r,w)'},
                                    @{Name='PIPOINT';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Connector Relays: A(r,w) | PI Data Collection Managers: A(r) | PI Users: A(r) | PI Interfaces: A(r) | PI Buffers: A(r,w) | PI Points&Analysis Creator: A(r,w) | PI Web Apps: A(r)'},
                                    @{Name='PIReplication';Security='piadmins: A(r,w) | PI Data Collection Managers: A(r)'},
                                    @{Name='PITransferRecords';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    @{Name='PITRUST';Security='piadmins: A(r,w)'},
                                    @{Name='PITUNING';Security='piadmins: A(r,w)'},
                                    @{Name='PIUSER';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Connector Relays: A(r,w) | PI Data Collection Managers: A(r) | PI Users: A(r) | PI Web Apps: A(r)'}
                                  )

        Foreach($DatabaseSecurityRule in $DatabaseSecurityRules)
        {
            PIDatabaseSecurity "SetDatabaseSecurity_$($DatabaseSecurityRule.Name)"
            {
                Name = $DatabaseSecurityRule.Name
                Security = $DatabaseSecurityRule.Security
                Ensure = "Present"
                PIDataArchive = $NodeName
            }
        }
        
        # Define security for default points
        $DefaultPIPoints = @(
                            'SINUSOID','SINUSOIDU','CDT158','CDM158','CDEP158',
                            'BA:TEMP.1','BA:LEVEL.1','BA:CONC.1','BA:ACTIVE.1','BA:PHASE.1'
                            )

        Foreach($DefaultPIPoint in $DefaultPIPoints)
        {
            PIPoint "DefaultPointSecurity_$DefaultPIPoint"
            {
                Name = $DefaultPIPoint
                Ensure = 'Present'
                PtSecurity = 'piadmins: A(r,w) | PI Buffers: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Interfaces: A(r) | PI Points&Analysis Creator: A(r,w) | PI Web Apps: A(r)'
                DataSecurity = 'piadmins: A(r,w) | PI Buffers: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Interfaces: A(r) | PI Points&Analysis Creator: A(r,w) | PI Web Apps: A(r)'
                PIDataArchive = $NodeName
            }
        }
    }
}