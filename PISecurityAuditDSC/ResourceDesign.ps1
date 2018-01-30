
Import-Module xDSCResourceDesigner

$Path = "$env:piauditrepo\PISecurityAuditDSC\Module\"
$CommonProperties = @{
    'Ensure' = (New-xDscResourceProperty -Name 'Ensure' -Type String -Attribute Write -ValidateSet 'Present', 'Absent');
    'PIDataArchive' = (New-xDscResourceProperty -Name 'PIDataArchive' -Type String -Attribute Required -Description 'PI Data Archive name for connection');
}

$Properties = @{}
$Properties += @{
    'Name' = (New-xDscResourceProperty -Name 'Name' -Type String -Attribute Key -Description 'unique name');
    'Default' = (New-xDscResourceProperty -Name 'Default' -Type String -Attribute Read -Description 'default value');
    'Value' = (New-xDscResourceProperty -Name 'Value' -Type String -Attribute Write -Description 'specified value');
}
$Properties += $CommonProperties
New-xDscResource -Name 'xPITuningParameter' -ModuleName 'PISecurityDSC' -FriendlyName 'PITuningParameter' -ClassVersion 0.1.0.0 -Property $Properties.Values -Path $Path

$Properties = @{}
$Properties += @{
    'Name' = (New-xDscResourceProperty -Name 'Name' -Type String -Attribute Key -Description 'unique name' );
    'AllowExplicitLogin' = (New-xDscResourceProperty -Name 'AllowExplicitLogin' -Type Boolean -Attribute Read );
    'AllowUseInTrusts' = (New-xDscResourceProperty -Name 'AllowUseInTrusts' -Type Boolean -Attribute Write );
    'AllowUseInMappings' = (New-xDscResourceProperty -Name 'AllowUseInMappings' -Type Boolean -Attribute Write );
    'CanDelete' = (New-xDscResourceProperty -Name 'CanDelete' -Type Boolean -Attribute Write );
    'Enabled' = (New-xDscResourceProperty -Name 'Enabled' -Type Boolean -Attribute Write );   
}
$Properties += $CommonProperties
New-xDscResource -Name 'xPIIdentity' -ModuleName 'PISecurityDSC' -FriendlyName 'PIIdentity' -ClassVersion 0.1.0.0 -Property $Properties.Values -Path $Path

$Properties = @{}
$Properties += @{
    'Hostmask' = (New-xDscResourceProperty -Name 'Hostmask' -Type String -Attribute Key );
    'Value' = (New-xDscResourceProperty -Name 'Value' -Type String -Attribute Write -ValidateSet 'Allow', 'Disallow', 'Unknown' );  
}
$Properties += $CommonProperties
New-xDscResource -Name 'xPIFirewall' -ModuleName 'PISecurityDSC' -FriendlyName 'PIFirewall' -ClassVersion 0.1.0.0 -Property $Properties.Values -Path $Path

$Properties = @{}
$Properties += @{ 
    'Name' = (New-xDscResourceProperty -Name 'Name' -Type String -Attribute Key );
    'Identity' = (New-xDscResourceProperty -Name 'Identity' -Type String -Attribute Write );
    'PrincipalName' = (New-xDscResourceProperty -Name 'PrincipalName' -Type String -Attribute Write );
    'Description' = (New-xDscResourceProperty -Name 'Description' -Type String -Attribute Write );
    'Disabled' = (New-xDscResourceProperty -Name 'Disabled' -Type Boolean -Attribute Write );  
}
$Properties += $CommonProperties
New-xDscResource -Name 'xPIMapping' -ModuleName 'PISecurityDSC' -FriendlyName 'PIMapping' -ClassVersion 0.1.0.0 -Property $Properties.Values -Path $Path

$Properties = @{}
$Properties += @{ 
    'Name' = (New-xDscResourceProperty -Name 'Name' -Type String -Attribute Key );
    'Security' = (New-xDscResourceProperty -Name 'Security' -Type String -Attribute Write );
}
$Properties += $CommonProperties

$Properties = @{}
$Properties += @{ 
    'Name' = (New-xDscResourceProperty -Name 'Name' -Type Sint32 -Attribute Key );
    'DataSecurity' = (New-xDscResourceProperty -Name 'DataSecurity' -Type String -Attribute Write );
    'PtSecurity' = (New-xDscResourceProperty -Name 'PtSecurity' -Type String -Attribute Write );
}
$Properties += $CommonProperties

New-xDscResource -Name 'xPIPoint' -ModuleName 'PISecurityDSC' -FriendlyName 'PIPoint' -ClassVersion 0.1.0.0 -Property $Properties.Values -Path $Path

$writeProperties = @(
                        'Identity',
                        'Description',
                        'NetworkPath', 
                        'IPAddress',
                        'NetMask',
                        'WindowsDomain',
                        'WindowsAccount', 
                        'ApplicationName'
                    )
$Properties = @{}
$Properties += @{ 
    'Name' = (New-xDscResourceProperty -Name 'Name' -Type String -Attribute Key );
    'Enabled' = (New-xDscResourceProperty -Name 'Enabled' -Type Boolean -Attribute Write );
}
foreach($Property in $writeProperties)
{
    $Properties += @{
        $Property = (New-xDscResourceProperty -Name $Property -Type String -Attribute Write );
    }
}
$Properties += $CommonProperties

New-xDscResource -Name 'xPITrust' -ModuleName 'PISecurityDSC' -FriendlyName 'PITrust' -ClassVersion 0.1.0.0 -Property $Properties.Values -Path $Path