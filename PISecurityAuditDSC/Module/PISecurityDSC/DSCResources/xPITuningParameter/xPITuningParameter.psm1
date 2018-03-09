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
        $Name,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    $PIResource = Get-PITuningParameter -Connection $Connection -Name $Name
    $Ensure = Get-PIResource_Ensure -PIResource $PIResource -Verbose:$VerbosePreference

    return @{
				    Name = $PIResource.Name;
                    Default = $PIResource.Default;
                    Ensure = $Ensure;
                    Value = $PIResource.Value;
                    PIDataArchive = $PIDataArchive;
            }
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $Value,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )
    
    $Connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIDataArchive
    
    if($Ensure -eq 'Absent')
    { 
        Reset-PITuningParameter -Connection $Connection -Name $Name 
    }
    else
    { 
        Set-PITuningParameter -Connection $Connection -Name $Name -Value $Value 
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
        $Name,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.String]
        $Value,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive
    )

    $PIResource = Get-TargetResource -Name $Name -PIDataArchive $PIDataArchive
    
    if($PIResource.Ensure -eq 'Present' -and $Ensure -eq 'Present')
    {
        return $($PIResource.Value -eq $Value -or ($(IsNullOrEmpty $PIResource.Value) -and $PIResource.Default -eq $Value))
    }
    else
    {
        return $($PIResource.Ensure -eq 'Absent' -and $Ensure -eq 'Absent')
    }
}

Export-ModuleMember -Function *-TargetResource