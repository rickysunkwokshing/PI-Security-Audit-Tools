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
        $PIDataArchive,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    $PIResource = Get-PIIdentity -Connection $Connection -Name $Name  
    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference

    return @{
                CanDelete = $PIResource.CanDelete
                IsEnabled = $PIResource.IsEnabled
                PIDataArchive = $PIDataArchive
                Ensure = $Ensure
                AllowUseInTrusts = $PIResource.AllowTrusts
                Name = $Name
                AllowExplicitLogin = $PIResource.AllowExplicitLogin
                AllowUseInMappings = $PIResource.AllowMappings
                Description = $PIResource.Description
            }
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.Boolean]
        $CanDelete=$true,

        [System.Boolean]
        $IsEnabled=$true,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure="Present",

        [System.Boolean]
        $AllowUseInTrusts=$true,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.Boolean]
        $AllowExplicitLogin=$false,

        [System.Boolean]
        $AllowUseInMappings=$true,

        [System.String]
        $Description=""
    )

    # Connect and get the resource
    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    $PIResource = Get-TargetResource -Name $Name -PIDataArchive $PIDataArchive
    
    # If the resource is supposed to be present we will either add it or set it.
    if($Ensure -eq 'Present')
    {  
        # Perform the set operation to correct the resource.
        if($PIResource.Ensure -eq "Present")
        {
            <# Since the identity is present, we must perform due diligence to preserve settings
            not explicitly defined in the config. Remove $PSBoundParameters and those not used 
            for the write operation (Ensure, PIDataArchive). #>
            $ParametersToOmit = @('Ensure', 'PIDataArchive') + $PSBoundParameters.Keys
            $ParametersToOmit | Foreach-Object { $null = $PIResource.Remove($_) }

            # Set the parameter values we want to keep to the current resource values.
            Foreach($Parameter in $PIResource.GetEnumerator())
            { 
                Set-Variable -Name $Parameter.Key -Value $Parameter.Value -Scope Local 
            }

            Write-Verbose "Setting PI Identity $($Name)"
            Set-PIIdentity -Connection $Connection -Name $Name `
                                -CanDelete:$CanDelete -Enabled:$IsEnabled `
                                -AllowUseInMappings:$AllowUseInMappings -AllowUseInTrusts:$AllowUseInTrusts `
                                -AllowExplicitLogin:$AllowExplicitLogin -Description $Description
        }
        else
        {
            <# Add the Absent identity. When adding the new identity, we do not need to worry about 
            clobbering existing properties because there are none. #>
            Write-Verbose "Adding PI Identity $($Name)"          
            Add-PIIdentity -Connection $Connection -Name $Name `
                                -DisallowDelete:$(!$CanDelete) -Disabled:$(!$IsEnabled) `
                                -DisallowUseInMappings:$(!$AllowUseInMappings) -DisallowUseInTrusts:$(!$AllowUseInTrusts) `
                                -Description $Description
        }
    }
    # If the resource is supposed to be absent we remove it.
    else
    {
        Write-Verbose "Removing PI Identity $($Name)"
        Remove-PIIdentity -Connection $Connection -Name $Name   
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.Boolean]
        $CanDelete,

        [System.Boolean]
        $IsEnabled,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Boolean]
        $AllowUseInTrusts,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.Boolean]
        $AllowExplicitLogin,

        [System.Boolean]
        $AllowUseInMappings,

        [System.String]
        $Description
    )

    $PIResource = Get-TargetResource -Name $Name -PIDataArchive $PIDataArchive
    
    return $(Compare-PIResourceGenericProperties -Desired $PSBoundParameters -Current $PIResource -Verbose:$VerbosePreference)
}

Export-ModuleMember -Function *-TargetResource