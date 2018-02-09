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
        $Path
    )

    $PIResource = Get-PIDataArchiveConnectionConfiguration -Name $Name
    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference

    if($Ensure -eq "Present")
    {
        $Port = $PIResource.ServerPort
        $Default = ($PIResource.ServiceUid -eq $(Get-PIDataArchiveConnectionConfiguration -Default).ServiceUid)
        $Collective = $PIResource.Binding.GetType().Name -eq 'PICollectiveBinding'

        # Acquire properties from appropriate member if collective
        if($Collective)
        {
            $PIResourceProperties = $PIResource.Binding.RoleSettings.Values.Where({$_.Name -eq $Path})
            if(IsNullOrEmpty $PIResourceProperties)
            {
                $Ensure = "Absent"
            }
            else
            {
                $OpenTimeout = $PIResourceProperties.OpenTimeout
                $OperationTimeout = $PIResourceProperties.OperationTimeout
                $Priority = $PIResourceProperties.Priority
            }
        }
        else
        {
            $OpenTimeout = $PIResource.Binding.OpenTimeout
            $OperationTimeout = $PIResource.Binding.OperationTimeout
            $Priority = $PIResource.Binding.RoleSettings.Values.Priority
            $Path = $PIResource.ServerPath
        }
    }

    return @{
                Name = $Name
                Path = $Path
                OpenTimeout = $OpenTimeout
                OperationTImeout = $OperationTimeout
                Priority = $Priority
                Port = $Port
                Default = $Default
                Collective = $Collective
                Ensure = $Ensure
            }
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $OpenTimeout="00:00:10",

        [System.String]
        $OperationTImeout="00:01:00",

        [System.Boolean]
        $Default,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.Int32]
        $Priority,

        [System.Int32]
        $Port=5450
    )

    $PIResource = Get-TargetResource -Name $Name -Path $Path
    
    if($Ensure -eq "Present")
    { 
        if($PIResource.Ensure -eq "Present")
        {   
            $PIDataArchiveConnectionConfigurationObject = Get-PIDataArchiveConnectionConfiguration -Name $Name
            if($PIResource.Collective)
            {
                Write-Verbose "Setting PI Data Archive collective KST entry: $($Name)"
                Set-PIDataArchiveConnectionConfiguration -MemberNode $Path -Priority $Priority `
                                                    -OpenTimeout $OpenTimeout -OperationTimeout $OperationTImeout `
                                                    -PIDataArchiveConnectionConfiguration $PIDataArchiveConnectionConfigurationObject
            }
            else
            {
                Write-Verbose "Setting PI Data Archive standalone KST entry: $($Name)"
                Set-PIDataArchiveConnectionConfiguration -Path $Path -Port $Port -Priority $Priority -Default:$Default `
                                                    -OpenTimeout $OpenTimeout -OperationTimeout $OperationTImeout `
                                                    -PIDataArchiveConnectionConfiguration $PIDataArchiveConnectionConfigurationObject
            }
        }
        else
        {
            Write-Verbose "Adding PI Data Archive KST entry: $($Name)" 
            Add-PIDataArchiveConnectionConfiguration -Name $Name -Path $Path -OpenTimeout $OpenTimeout -OperationTimeout $OperationTImeout -Port $Port -DefaultServer:$Default
        }    
    }
    else
    { 
        Write-Verbose "Removing PI Data Archive KST entry: $($Name)"
        Remove-PIDataArchiveConnectionConfiguration -Name $Name
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $OpenTimeout,

        [parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [System.String]
        $OperationTImeout,

        [System.Boolean]
        $Default,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.Int32]
        $Priority,

        [System.Int32]
        $Port
    )

    $PIResource = Get-TargetResource -Name $Name -Path $Path

    return $(Compare-PIResourceGenericProperties -Desired $PSBoundParameters -Current $PIResource -Verbose:$VerbosePreference)
}

Export-ModuleMember -Function *-TargetResource