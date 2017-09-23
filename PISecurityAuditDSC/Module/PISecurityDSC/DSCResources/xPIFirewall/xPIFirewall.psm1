Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonResourceHelper.psm1')

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Hostmask,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    $PIResource = Get-PIFirewall -Connection $Connection -Hostmask $Hostmask -ErrorAction SilentlyContinue
    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference

    return @{
                Ensure = $Ensure
                Value = $PIResource.Value
                Hostmask = $PIResource.Hostmask
                PIDataArchive = $PIDataArchive
            }
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [ValidateSet("Allow","Disallow","Unknown")]
        [System.String]
        $Value,

        [parameter(Mandatory = $true)]
        [System.String]
        $Hostmask,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    
    if($Ensure -eq 'Absent')
    { 
        Remove-PIFirewall -Connection $Connection -Hostmask $Hostmask
    }
    else
    { 
        Add-PIFirewall -Connection $Connection -Hostmask $Hostmask -Value $Value 
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [ValidateSet("Allow","Disallow","Unknown")]
        [System.String]
        $Value,

        [parameter(Mandatory = $true)]
        [System.String]
        $Hostmask,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $PIResource = Get-TargetResource -Hostmask $Hostmask -PIDataArchive $PIDataArchive
    
    if($PIResource.Ensure -eq 'Present' -and $Ensure -eq 'Present')
    {
        Write-Verbose "Testing desired: $Value against current: $($PIResource.Value)"
        return $($Value -and $PIResource.Value)
    }
    return $($PIResource.Ensure -eq 'Absent' -and $Ensure -eq 'Absent')
}

Export-ModuleMember -Function *-TargetResource