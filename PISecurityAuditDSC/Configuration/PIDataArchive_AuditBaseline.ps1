Configuration PIDataArchive_AuditBaseline
{
    param(
        [String]$ComputerName = "localhost"
         )

    Import-DscResource -ModuleName PISecurityDSC

    Node $ComputerName
    {
        
        PITuningParameter EditDays
        {
            Name = "EditDays"
            Value = "180"
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }

        # Enumerate default identities to disable
        $DefaultPIIdentities = @(
                                    'PIWorld'
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
        
        # Restrict use of the piadmin superuser
        PIIdentity Restrict_piadmin
        {
            Name = "piadmin"
            AllowUseInTrusts = $false
            AllowUseInMappings = $false
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }
    }
}
PIDataArchive_AuditBaseline