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
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    $PIResource = Get-PIPoint -Connection $Connection -Name $Name  -Attributes @('ptsecurity','datasecurity')
    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference

    return @{
                PtSecurity = $PIResource.Attributes.ptsecurity
                Name = $Name
                Ensure = $Ensure
                DataSecurity = $PIResource.Attributes.datasecurity
                PIDataArchive = $PIDataArchive
            }
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $PtSecurity,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $DataSecurity,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    
    if($Ensure -eq 'Absent')
    { 
        Remove-PIPoint -Connection $Connection -Name $Name -ErrorAction SilentlyContinue
    }
    else
    { 
        Set-PIPoint -Connection $Connection -Name $Name -Attributes @{ ptsecurity=$PtSecurity; datasecurity=$DataSecurity } 
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $PtSecurity,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $DataSecurity,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $PIResource = Get-TargetResource -Name $Name -PIDataArchive $PIDataArchive
    
    if($PIResource.Ensure -eq 'Present' -and $Ensure -eq 'Present')
    {
        $PtSecurityMatch = Compare-PIDataArchiveACL -Desired $PtSecurity -Current $PIResource.PtSecurity
        $DataSecurityMatch = Compare-PIDataArchiveACL -Desired $DataSecurity -Current $PIResource.DataSecurity
        
        return $($PtSecurityMatch -and $DataSecurityMatch)
    }
    else
    {
        return $($PIResource.Ensure -eq 'Absent' -and $Ensure -eq 'Absent')
    }
}

Export-ModuleMember -Function *-TargetResource