Configuration PISecurityAuditDSCBaseline
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
        
        PIIdentity no_piadmin
        {
            Name = "piadmin"
            AllowUseInTrusts = $false
            AllowUseInMappings = $false
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }
    }
}
PISecurityAuditDSCBaseline
