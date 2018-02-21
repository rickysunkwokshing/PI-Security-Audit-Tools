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
        $Name
    )

    $PIResource = Get-AFServer -Name $Name
    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference
    
    return @{
                Ensure = $Ensure
                Name = $Name
                Timeout = $PIResource.ConnectionInfo.Timeout
                Path = $PIResource.ConnectionInfo.Host
                Account = $PIResource.ConnectionInfo.AccountName
                Port = $PIResource.ConnectionInfo.Port
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

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.String]
        $Timeout,

        [System.String]
        $Path,

        [System.String]
        $Account,

        [System.Int32]
        $Port
    )

    $PIResource = Get-TargetResource -Name $Name

    # If the resource is supposed to be present we will either add it or set it.
    if($Ensure -eq 'Present')
    {  
        $ParameterTable = @{
            Path = $Path
            Port = $Port
            Timeout = $Timeout
        }
        
        if($PIResource.Ensure -eq "Present")
        {
            if((IsNullOrEmpty $Account) -and !(IsNullOrEmpty $PIResource.Account))
            {
                Write-Verbose "Removing AF Server KST entry to clear account: $($Name)"
                Remove-AFServer -Name $PIResource.Name
                Write-Verbose "Adding AF Server KST entry: $($Name)"          
                Add-AFServer @ParameterTable -Name $Name 
            }
            else
            {
                if(!(IsNullOrEmpty $Account))
                {
                    $ParameterTable += @{ Account = $Account }
                }
                Write-Verbose "Setting AF Server KST entry: $($Name)" 
                $ParameterTable += @{ AFServer = $(Get-AFServer -Name $Name) }
                Set-AFServer @ParameterTable
            }
        }
        else
        { 
            Write-Verbose "Adding AF Server KST entry: $($Name)"          
            Add-AFServer @ParameterTable -Name $Name
        }
    }
    # If the resource is supposed to be absent we remove it.
    else
    {
        Write-Verbose "Removing AF Server KST entry: $($PIResource.Name)"
        Remove-AFServer -Name $PIResource.Name  
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

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.String]
        $Timeout,

        [System.String]
        $Path,

        [System.String]
        $Account,

        [System.Int32]
        $Port
    )

    $PIResource = Get-TargetResource -Name $Name
    
    return $(Compare-PIResourceGenericProperties -Desired $PSBoundParameters -Current $PIResource -Verbose:$VerbosePreference)
}

Export-ModuleMember -Function *-TargetResource