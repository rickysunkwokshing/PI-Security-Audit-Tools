Configuration PISecurityDSCBaseline
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
            Server = "spacemantimez"
        }
    }
}
PISecurityDSCBaseline
