Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                               -ChildPath 'CommonResourceHelper.psm1')

function Get-NTAccount
{
    [CmdletBinding()]
    param
    (
        [string]$AccountName
    )

    $splitAccount = $AccountName -split '\\'
    if($splitAccount.Count -eq 1)
    {
        # No domain specified, assumes local user
        $ntAccount = New-Object System.Security.Principal.NTAccount -ArgumentList $splitAccount[0]
    }
    elseif($splitAccount.Count -eq 2)
    {
        # Pass both domain and username 
        $ntAccount = New-Object System.Security.Principal.NTAccount `
            -ArgumentList $splitAccount[0], $splitAccount[1]
    }
    else
    {
        $ErrorActionPreference = 'Stop'
        throw "Invalid Account name specified."
    }

    # Test if account may be resolved correctly
    $oldErrPref = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try
    {
        $SID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch
    {
        throw "Could not translate Account name to security identifier."
    }
    finally
    {
        $ErrorActionPreference = $oldErrPref
    }

    return $ntAccount
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $AFServer,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    # Load AF SDK. Calling this while it's already loaded shouldn't be harmful
    $loaded = [System.Reflection.Assembly]::LoadWithPartialName("OSIsoft.AFSDK")
    if ($null -eq $loaded) {
        $ErrorActionPreference = 'Stop'
        throw "AF SDK could not be loaded"
    }

    $piSystems = New-Object OSIsoft.AF.PISystems
    $AF = $piSystems | Where-Object Name -EQ $AFServer
    if($null -eq $AF)
    {
        $ErrorActionPreference = 'Stop'
        throw "Could not locate AF Server '$AFServer' in known servers table"
    }

    $mapping = $AF.SecurityMappings[$Name]

    $Ensure = Get-PIResource_Ensure -PIResource $mapping -Verbose:$VerbosePreference

    $returnValue = @{
        AFServer = $AFServer;
        Name = $mapping.Name;
        Description = $mapping.Description;
        Account = $mapping.AccountDisplayName;
        AFIdentityName = $mapping.SecurityIdentity.Name;
        Ensure = $Ensure;
    }

    $returnValue
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $Description,

        [System.String]
        $AFIdentityName,

        [parameter(Mandatory = $true)]
        [System.String]
        $AFServer,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $Account
    )

    # Load AF SDK. Calling this while it's already loaded shouldn't be harmful
    $loaded = [System.Reflection.Assembly]::LoadWithPartialName("OSIsoft.AFSDK")
    if ($null -eq $loaded) {
        $ErrorActionPreference = 'Stop'
        throw "AF SDK could not be loaded"
    }

    $piSystems = New-Object OSIsoft.AF.PISystems
    $AF = $piSystems | Where-Object Name -EQ $AFServer
    if($null -eq $AF)
    {
        $ErrorActionPreference = 'Stop'
        throw "Could not locate AF Server '$AFServer' in known servers table"
    }

    $PIResource = Get-TargetResource -Name $Name -AFServer $AFServer

    if($Ensure -eq "Present")
    {
        # Check if the specified Account and AFIdentityName are valid, stop if not.
        $ErrorActionPreference = 'Stop'
        $ntAccount = Get-NTAccount -AccountName $Account # will throw exception if invalid
        $identity = $AF.SecurityIdentities[$AFIdentityName]
        if($null -eq $identity)
        {
            throw "Could not find existing AF Identity with name '$AFIdentityName'."
        }

        if($PIResource.Ensure -eq "Present")
        {
            <# Some special handling required if specified Account is different
            than the resource's current Account. Must recreate the AF Mapping 
            because the mapping's Account is read-only. #>
            $deleteRequired = $false
            if($Account -ne $PIResource.Account) { $deleteRequired = $true }

            <# Since the identity is present, we must perform due diligence to preserve settings
            not explicitly defined in the config. Remove $PSBoundParameters and those not used 
            for the write operation (Ensure, AFServer). #>
            $ParametersToOmit = @('Ensure', 'AFServer') + $PSBoundParameters.Keys
            $ParametersToOmit | Foreach-Object { $null = $PIResource.Remove($_) }

            # Set the parameter values we want to keep to the current resource values.
            Foreach($Parameter in $PIResource.GetEnumerator())
            { 
                Set-Variable -Name $Parameter.Key -Value $Parameter.Value -Scope Local 
            }

            Write-Verbose "Setting AF Mapping '$Name'"
            if($deleteRequired)
            {
                # Delete the existing mapping
                $mapping = $AF.SecurityMappings[$Name]
                $AF.SecurityMappings.Remove($mapping)
                $mapping.CheckIn()

                # Create a new mapping with the specified Account
                $mapping = $AF.SecurityMappings.Add($Name, $ntAccount, $identity, $null)
            }
            else
            {
                $mapping = $AF.SecurityMappings[$Name]
                $mapping.SecurityIdentity = $identity
            }
            $mapping.Description = $Description
            $mapping.CheckIn()
        }
        else
        {
            Write-Verbose "Adding AF Mapping '$Name'"
            $mapping = $AF.SecurityMappings.Add($Name, $ntAccount, $identity, $null)
            $mapping.Description = $Description
            $mapping.CheckIn()
        }
    }
    else
    {
        Write-Verbose "Removing AF Mapping '$Name'"
        $mapping = $AF.SecurityMappings[$Name]
        $AF.SecurityMappings.Remove($mapping) | Out-Null
        $mapping.CheckIn()
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $Description,

        [System.String]
        $AFIdentityName,

        [parameter(Mandatory = $true)]
        [System.String]
        $AFServer,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $Account
    )

    $PIResource = Get-TargetResource -Name $Name -AFServer $AFServer -Verbose:$VerbosePreference

    return (Compare-PIResourceGenericProperties -Desired $PSBoundParameters -Current $PIResource)
}


Export-ModuleMember -Function *-TargetResource

