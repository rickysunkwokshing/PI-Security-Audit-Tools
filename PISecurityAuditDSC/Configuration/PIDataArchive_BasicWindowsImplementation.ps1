Configuration PIDataArchive_BasicWindowsImplementation
{
    param(
        [String]$ComputerName = "localhost"
         )

    Import-DscResource -ModuleName PISecurityDSC

    Node $ComputerName
    {
        # Enumerate Basic WIS Roles
        $BasicWISRoles = @(
                            @{Name='PI Buffers';Description='Identity for PI Buffer Subsystem and PI Buffer Server';},
                            @{Name='PI Interfaces';Description='Identity for PI Interfaces';},
                            @{Name='PI Users';Description='Identity for the Read-only users';},
                            @{Name='PI Points&Analysis Creator';Description='Identity for PIACEService, PIAFService and users that can create and edit PI Points';}
                            @{Name='PI Web Apps';Description='Identity for PI Vision, PI WebAPI, and PI WebAPI Crawler';}
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
                PIDataArchive = $ComputerName
            }
        } 

        # Enumerate default identities to disable
        $DefaultPIIdentities = @(
                                    'PIOperators',
                                    'PISupervisors',
                                    'PIEngineers',
                                    'PIWorld',
                                    'pidemo',
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
                PIDataArchive = $ComputerName
            }
        }
        
        # Set PI Mappings 
        PIMapping DefaultMapping_Admins
        {
            Name = 'Windows_S-1-5-32-544'
            PrincipalName = 'BUILTIN\Administrators'
            Identity = "piadmins"
            Disabled = $false
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }

        PIMapping DefaultMapping_Everyone
        {
            Name = 'Windows_S-1-1-0'
            PrincipalName = '\Everyone'
            Identity = "PI Users"
            Disabled = $false
            Ensure = "Present"
            PIDataArchive = $ComputerName
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
                                    @{Name='PIDBSEC';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Web Apps: A(r)'},
                                    @{Name='PIDS';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Points&Analysis Creator: A(r,w)'},
                                    @{Name='PIHeadingSets';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    @{Name='PIMAPPING';Security='piadmins: A(r,w) | PI Web Apps: A(r)'},
                                    @{Name='PIModules';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    @{Name='PIMSGSS';Security='piadmins: A(r,w) | PIWorld: A(r,w)| PI Users: A(r,w)'},
                                    @{Name='PIPOINT';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Interfaces: A(r) | PI Buffers: A(r,w) | PI Points&Analysis Creator: A(r,w) | PI Web Apps: A(r)'},
                                    @{Name='PIReplication';Security='piadmins: A(r,w)'},
                                    @{Name='PITransferRecords';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'},
                                    @{Name='PITRUST';Security='piadmins: A(r,w)'},
                                    @{Name='PITUNING';Security='piadmins: A(r,w)'},
                                    @{Name='PIUSER';Security='piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Web Apps: A(r)'}
                                  )

        Foreach($DatabaseSecurityRule in $DatabaseSecurityRules)
        {
            PIDatabaseSecurity "SetDatabaseSecurity_$($DatabaseSecurityRule.Name)"
            {
                Name = $DatabaseSecurityRule.Name
                Security = $DatabaseSecurityRule.Security
                Ensure = "Present"
                PIDataArchive = $ComputerName
            }
        }
        
    }
}
PIDataArchive_BasicWindowsImplementation