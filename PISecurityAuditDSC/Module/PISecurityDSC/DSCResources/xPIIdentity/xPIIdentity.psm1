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

    Write-Verbose "Connecting to: $($PIDataArchive)"
    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
	
    Write-Verbose "Getting PI Identity: $($Name)"
    $PIResource = Get-PIIdentity -Connection $Connection -Name $Name  
    
    if($null -eq $PIResource)
    { 
        $Ensure = "Absent" 
    }
    else
    { 
        $Ensure = "Present"
        Foreach($Property in $($PIResource | Get-Member -MemberType Property | select -ExpandProperty Name))
        {
            Write-Verbose "GetResult: $($Property): $($PIResource.$Property)."
        }
    }

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
            # Since the identity is present, we must perform due diligence to preserve settings
            # not explicitly defined in the config. Remove $PSBoundParameters and those not used 
            # for the write operation (Ensure, PIDataArchive).
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
            # Add the Absent identity. When adding the new identity, we do not need to worry about 
            # clobbering existing properties because there are none.
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
    
    # Take out parameters that are not actionable
    @('Ensure','PIDataArchive') | Foreach-Object { $null = $PSBoundParameters.Remove($_) }

    $PIResource = Get-TargetResource -Name $Name -PIDataArchive $PIDataArchive
    
    if($PIResource.Ensure -eq 'Absent')
    {
        Write-Verbose "PI Identity $Name is Absent"
        if($Ensure -eq 'Absent')
        { 
            return $true 
        }
        else
        { 
            return $false 
        }
    }
    else
    {
        Write-Verbose "PI Identity $Name is Present"
        if($Ensure -eq 'Absent')
        { 
            return $false
        }
        else
        {
            Foreach($Parameter in $PSBoundParameters.GetEnumerator())
            {
                # Nonrelevant fields can be skipped.
                if($PIResource.Keys -contains $Parameter.Key)
                {
                    # Make sure all applicable fields match.
                    if($($PIResource.$($Parameter.Key)) -ne $Parameter.Value)
                    {
                        return $false
                    }
                }
            } 
            return $true 
        }
    }
}

Export-ModuleMember -Function *-TargetResource