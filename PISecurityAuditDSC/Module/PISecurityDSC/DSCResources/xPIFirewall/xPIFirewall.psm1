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
        $Hostmask,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    $PIResource = Get-PIFirewall -Connection $Connection -Hostmask $Hostmask -ErrorAction SilentlyContinue
    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference

    return @{
                Ensure = $Ensure
                Value = $PIResource.Access
                Hostmask = $PIResource.Hostmask
                PIDataArchive = $PIDataArchive
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

        [ValidateSet("Allow","Disallow","Unknown")]
        [System.String]
        $Value,

        [parameter(Mandatory = $true)]
        [System.String]
        $Hostmask,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    
    if($Ensure -eq 'Absent')
    { 
        Remove-PIFirewall -Connection $Connection -Hostmask $Hostmask
    }
    else
    { 
        Add-PIFirewall -Connection $Connection -Hostmask $Hostmask -Value $Value 
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

        [ValidateSet("Allow","Disallow","Unknown")]
        [System.String]
        $Value,

        [parameter(Mandatory = $true)]
        [System.String]
        $Hostmask,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $PIResource = Get-TargetResource -Hostmask $Hostmask -PIDataArchive $PIDataArchive
    
    return $(Compare-PIResourceGenericProperties -Desired $PSBoundParameters -Current $PIResource -Verbose:$VerbosePreference)
}

Export-ModuleMember -Function *-TargetResource