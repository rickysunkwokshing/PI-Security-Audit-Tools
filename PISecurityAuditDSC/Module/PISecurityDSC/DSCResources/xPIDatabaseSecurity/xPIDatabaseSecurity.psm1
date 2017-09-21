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
    $PIResource = Get-PIDatabaseSecurity -Connection $Connection -Name $Name
    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference

    return @{
                Security = $PIResource.Security.ToString()
                Name = $Name
                Ensure = $Ensure
                PIDataArchive = $PIDataArchive
            }
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Security,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    
    if($Ensure -eq 'Absent')
    { 
        Set-PIDatabaseSecurity -Connection $Connection -Name $Name -Security "" 
    }
    else
    { 
        Set-PIDatabaseSecurity -Connection $Connection -Name $Name -Security $Security 
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $Security,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $PIResource = Get-TargetResource -Name $Name -PIDataArchive $PIDataArchive

    if($PIResource.Ensure -eq 'Present')
    {
        if($Ensure -eq 'Present')
        { 
            if($PIResource.Security -eq $Security)
            { 
                $Result = $true 
            }
            else 
            { 
                $Result = $false 
            }
        }
        else
        {
            $Result = $false
        }    
    }
    else
    {
        if($Ensure -eq 'Present')
        { 
            $Result = $false 
        }
        else
        { 
            $Result = $true 
        }
    }
    Write-Verbose $Result
    return $Result
}


Export-ModuleMember -Function *-TargetResource

