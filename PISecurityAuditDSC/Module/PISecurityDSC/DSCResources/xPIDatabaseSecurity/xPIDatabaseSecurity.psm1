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
        <# Setting database security to only piadmin access is as restrictive as it can be 
        since piadmin cannot be denied. #>
        Set-PIDatabaseSecurity -Connection $Connection -Name $Name -Security "piadmin: A(r,w)" 
    }
    else
    { 
        if($Name -eq 'PIBATCHLEGACY')
        {
            if($(Get-Service pibatch -ComputerName $PIDataArchive).Status -eq 'Running')
            {
                Set-PIDatabaseSecurity -Connection $Connection -Name $Name -Security $Security
            }
            else
            {
                Write-Verbose "PI Batch Subsystem must be running to edit database security for PIBATCHLEGACY"
                Write-Verbose "PI Batch Subsystem is no longer needed.  It is recommended to disable the service"
                Write-Verbose "and ignore the PIBATCHLEGACY database security entry."
            }
        }
        elseif($Name -eq 'AFLINK')
        {
            if($(Get-Service piaflink -ComputerName $PIDataArchive).Status -eq 'Running')
            {
                Set-PIDatabaseSecurity -Connection $Connection -Name $Name -Security $Security
            }
            else
            {
                Write-Verbose "PI AF Link Subsystem must be running to edit database security for PIAFLINK"
                Write-Verbose "If the system does not require MDB synchronization, you can disable the service"
                Write-Verbose "and ignore teh PIAFLINK database security entry."
            }
        }
        else
        {
            Set-PIDatabaseSecurity -Connection $Connection -Name $Name -Security $Security 
        }
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

    if($PIResource.Ensure -eq 'Present' -and $Ensure -eq 'Present')
    {
        return $(Compare-PIDataArchiveACL -Desired $Security -Current $PIResource.Security -Verbose:$VerbosePreference)    
    }
    else
    {
        return $($PIResource.Ensure -eq 'Absent' -and $Ensure -eq 'Absent')
    }
}

Export-ModuleMember -Function *-TargetResource