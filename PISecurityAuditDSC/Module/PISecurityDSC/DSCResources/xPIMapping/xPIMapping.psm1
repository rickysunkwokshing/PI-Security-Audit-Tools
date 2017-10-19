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
        $PrincipalName,

        [System.String]
        $Name
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    
    $PIResource = Get-PIMapping -Connection $Connection | Where-Object { ($_.PrincipalName.ToLower() -eq $PrincipalName.ToLower()) }

    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference

    return @{
                PrincipalName = $PrincipalName
                Description = $PIResource.Description
                PIDataArchive = $PIDataArchive
                Ensure = $Ensure
                Enabled = $PIResource.IsEnabled
                Name = $PIResource.Name
                Identity = $PIResource.Identity
            }
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $PrincipalName,

        [System.String]
        $Description="",

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Boolean]
        $Enabled=$true,

        [System.String]
        $Name,

        [System.String]
        $Identity
    )

   # Connect and get the resource
    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    $PIResource = Get-TargetResource -PrincipalName $PrincipalName -PIDataArchive $PIDataArchive
    
    # If the resource is supposed to be present we will either add it or set it.
    if($Ensure -eq 'Present')
    {  
        # Perform the Set operation to correct the resource.
        if($PIResource.Ensure -eq "Present")
        {
            # If the configuration explicitly uses a name different than 
            # the current resource has, we rename it.
            if(!$(IsNullOrEmpty $Name) -and $Name -ne $PIResource.Name)
            {
                # Remove the mapping with the wrong name
                Write-Verbose "Removing PI Mapping $($Name) before adding $($PIResource.Name)"
                Remove-PIMapping -Connection $Connection -Name $PIResource.Name
                
                # Add the Absent mapping. 
                Write-Verbose "Adding PI Mapping $($Name)"          
                Add-PIMapping -Connection $Connection -Name $Name `
                                -Identity $Identity -PrincipalName $PrincipalName `
                                -Description $Description -Disabled:$(!$Enabled)
            }
            else
            {
                # Since the mapping is present, we must perform due diligence to preserve settings
                # not explicitly defined in the config. Remove $PSBoundParameters and those not used 
                # for the write operation (Ensure, PIDataArchive).
                $ParametersToOmit = @('Ensure', 'PIDataArchive') + $PSBoundParameters.Keys
                $ParametersToOmit | Foreach-Object { $null = $PIResource.Remove($_) }

                # Set the parameter values we want to keep to the current resource values.
                Foreach($Parameter in $PIResource.GetEnumerator())
                { 
                    Set-Variable -Name $Parameter.Key -Value $Parameter.Value -Scope Local 
                }

                Write-Verbose "Setting PI Mapping $($Name)"
                Set-PIMapping -Connection $Connection -Name $Name `
                                -Identity $Identity -PrincipalName $PrincipalName `
                                -Description $Description -Disabled:$(!$Enabled)
            } 
        }
        else
        {
            if($(IsNullOrEmpty $Name))
            {
                $Name = $PrincipalName
            }
            # Add the Absent mapping. 
            Write-Verbose "Adding PI Mapping $($Name)"          
            Add-PIMapping -Connection $Connection -Name $Name `
                            -Identity $Identity -PrincipalName $PrincipalName `
                            -Description $Description -Disabled:$(!$Enabled)
        }
    }
    # If the resource is supposed to be absent we remove it.
    else
    {
        Write-Verbose "Removing PI Mapping $($PIResource.Name)"
        Remove-PIMapping -Connection $Connection -Name $PIResource.Name   
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $PrincipalName,

        [System.String]
        $Description,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Boolean]
        $Enabled,

        [System.String]
        $Name,

        [System.String]
        $Identity
    )

    $PIResource = Get-TargetResource -PrincipalName $PrincipalName -PIDataArchive $PIDataArchive
    
    return $(Compare-PIResourceGenericProperties -Desired $PSBoundParameters -Current $PIResource -Verbose:$VerbosePreference)
}


Export-ModuleMember -Function *-TargetResource