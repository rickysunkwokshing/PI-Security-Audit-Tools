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

    if($PIResource.Ensure -eq 'Present')
    {
        if($Ensure -eq 'Present')
        {
            Write-Verbose "Testing against value: $Security"
            $DoACLsMatch = Test-PIDatabaseSecurityACL -DesiredSecurity $Security -CurrentSecurity $PIResource.Security
            if($DoACLsMatch)
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
    Write-Verbose "Test result: $Result"
    return $Result
}

function Test-PIDatabaseSecurityACL
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [parameter(Mandatory=$true)]
        [System.String]
        $DesiredSecurity,
        
        [parameter(Mandatory=$true)]
        [System.String]
        $CurrentSecurity
    )

    $DesiredSecurityTable = Convert-PISecurityStringToHashTable -SecurityString $DesiredSecurity
    $CurrentSecurityTable = Convert-PISecurityStringToHashTable -SecurityString $CurrentSecurity
    if($CurrentSecurityTable.Count -ne $DesiredSecurityTable.Count)
    {
        return $false
    }
    else
    {
        foreach($Entry in $CurrentSecurityTable.GetEnumerator())
        {
            if(-not($DesiredSecurityTable.ContainsKey($Entry.Name)))
            {
                return $false
            }
            else
            {
                if($DesiredSecurityTable[$Entry.Name] -ne $Entry.Value)
                {
                    return $false
                }
            }
        }
        return $true
    }
}

Export-ModuleMember -Function *-TargetResource

