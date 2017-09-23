Configuration PIDataArchive_AuditBaseline
{
    param(
        [String]$ComputerName = 'localhost',
        # Days to allow edits
        [Int32]$DaysToAllowEdit=365,
        # Maximum time for a query to run
        [ValidateRange(60,300)]
        [Int32]$Archive_MaxQueryExecutionSec=260,
        # Autotrustconfig
        [ValidateSet('0','1')]
        [Int32]$AutoTrustConfig=0,
        # Host masks for valid PI Data Archive clients
        [String[]]$PIFirewall_Hostmasks = @('10.*.*.*','192.168.*.*'),
        # Authentication policy: 
        # 3 (block explicit login) 
        # 19 (block sdk trusts)
        # 51 (block all trusts)
        [ValidateSet('3','19','51')]
        [Int32]$Server_AuthenticationPolicy='51'
         )

    Import-DscResource -ModuleName PISecurityDSC

    Node $ComputerName
    {
        # AU20001 - Disable PIWorld
        PIIdentity "AU20001: PIWorld usage"
        {
            Name = 'PIWorld'
            IsEnabled = $false
            AllowUseInTrusts = $false
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }
        
        # AU20002 - Restrict use of the piadmin superuser
        PIIdentity 'AU20002: piadmin usage'
        {
            Name = "piadmin"
            AllowUseInTrusts = $false
            AllowUseInMappings = $false
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }

        # AU20004 - Specify EditDays
        PITuningParameter 'AU20004: EditDays'
        {
            Name = "EditDays"
            Value = $DaysToAllowEdit
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }

        # AU20005 - Auto Trust configuration
        PITuningParameter 'AU20005: AutoTrustConfig'
        {
            Name = "AutoTrustConfig"
            Value = $AutoTrustConfig
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }

        # AU20006 - Expensive query protection
        PITuningParameter 'AU20006: Archive_MaxQueryExecutionSec'
        {
            Name = "Archive_MaxQueryExecutionSec"
            Value = $Archive_MaxQueryExecutionSec
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }

        # AU20007 - Explicit Login Disabled
        PITuningParameter 'AU20007: Server_AuthenticationPolicy'
        {
            Name = "Server_AuthenticationPolicy"
            Value = $Server_AuthenticationPolicy
            Ensure = "Present"
            PIDataArchive = $ComputerName
        }
        
        # AU20011 - PI Firewall
        $i = 0
        foreach($Hostmask in $PIFirewall_Hostmasks)
        {
            PIFirewall "AU20011 - PIFirewall Add $i"
            {
                Hostmask = $Hostmask
                Ensure = "Present"
                Value = "Allow" 
                PIDataArchive = $ComputerName
            }
            $i++
        }

        PIFirewall "AU20011 - PIFirewall Remove Default"
        {
            Hostmask = '*.*.*.*'
            Ensure = "Absent"
            Value = "Allow" 
            PIDataArchive = $ComputerName
            DependsOn = "[PIFirewall]AU20011 - PIFirewall Add 0"
        }
    }
}
PIDataArchive_AuditBaseline