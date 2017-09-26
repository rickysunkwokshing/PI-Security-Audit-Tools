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

    $PIResource = Get-TargetResource -Name $Name -PIDataArchive $PIDataArchive
    
    return $(Compare-PIResourceGenericProperties -Desired $PSBoundParameters -Current $PIResource)
}

Export-ModuleMember -Function *-TargetResource