# ************************************************************************
# *
# * Copyright 2016 OSIsoft, LLC
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# * 
# *   <http://www.apache.org/licenses/LICENSE-2.0>
# * 
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *
# ************************************************************************

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

    $identity = $AF.SecurityIdentities[$Name]

    $Ensure = Get-PIResource_Ensure -PIResource $identity -Verbose:$VerbosePreference

    $returnValue = @{
        AFServer = $AFServer;
        Name = $identity.Name;
        Description = $identity.Description;
        IsEnabled = $identity.IsEnabled;
        Ensure = $Ensure;
    }

    $returnValue
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.Boolean]
        $IsEnabled = $true,

        [parameter(Mandatory = $true)]
        [System.String]
        $AFServer,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [String]
        $Description = ''
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
        if($PIResource.Ensure -eq "Present")
        {
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

            Write-Verbose "Setting AF Identity '$Name'"
            $identity = $AF.SecurityIdentities[$Name]
            $identity.Description = $Description
            $identity.IsEnabled = $IsEnabled
            $identity.CheckIn()
        }
        else
        {
            Write-Verbose "Adding AF Identity '$Name'"
            $identity = $AF.SecurityIdentities.Add($Name)
            $identity.Description = $Description
            $identity.IsEnabled = $IsEnabled
            $identity.CheckIn()
        }
    }
    else
    {
        Write-Verbose "Removing AF Identity '$Name'"
        $identity = $AF.SecurityIdentities[$Name]
        $AF.SecurityIdentities.Remove($identity) | Out-Null
        $identity.CheckIn()
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.Boolean]
        $IsEnabled = $true,

        [parameter(Mandatory = $true)]
        [System.String]
        $AFServer,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure = "Present",

        [String]
        $Description = ''
    )

    $PIResource = Get-TargetResource -Name $Name -AFServer $AFServer

    return (Compare-PIResourceGenericProperties -Desired $PSBoundParameters -Current $PIResource)
}


Export-ModuleMember -Function *-TargetResource

