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

function Get-PIResource_Ensure
{
    [CmdletBinding()]
    param(
        [object]
        $PIResource
    )

    if($null -eq $PIResource)
    { 
        $Ensure = "Absent" 
    }
    else
    { 
        $Ensure = "Present"
        Foreach($Property in $($PIResource | Get-Member -MemberType Property | select -ExpandProperty Name))
        {
            if($null -eq $PIResource.$Property)
            {
                $Value = 'NULL'
            }
            else
            {
                $Value = $PIResource.$Property.ToString()
            }
            Write-Verbose "GetResult: $($Property): $($Value)."
        }
    }

    Write-Verbose "Ensure: $($Ensure)"

    return $Ensure
}

function Compare-PIDataArchiveACL
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [parameter(Mandatory=$true)]
        [System.String]
        $Desired,
        
        [parameter(Mandatory=$true)]
        [System.String]
        $Current
    )
    
    Write-Verbose "Testing desired: $Desired against current: $Current"

    return $($(Compare-Object -ReferenceObject $Desired.Split('|').Trim() -DifferenceObject $Current.Split('|').Trim()).Length -eq 0)
}

function Compare-PIResourceGenericProperties
{
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [System.Object]
        $Desired,
        
        [parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        $Current
    )

    if($Current.Ensure -eq 'Present' -and $Desired['Ensure'] -eq 'Present')
    {
        Foreach($Parameter in $Desired.GetEnumerator())
        {
            # Nonrelevant fields can be skipped.
            if($Current.Keys -contains $Parameter.Key)
            {
                # Make sure all applicable fields match.
                Write-Verbose "Checking $($Parameter.Key) current value: ($($Current.$($Parameter.Key))) against desired value: ($($Parameter.Value))"
                if($($Current.$($Parameter.Key)) -ne $Parameter.Value)
                {
                    Write-Verbose "Undesired property found: $($Parameter.Key)"
                    return $false
                }
            }
        } 

        Write-Verbose "No undesired properties found."
        return $true
    }
    else
    {
        return $($Current.Ensure -eq 'Absent' -and $Desired['Ensure'] -eq 'Absent')
    }
}

function Set-PIResourceParametersPreserved
{
    param(
        [parameter(Mandatory=$true)]
        [alias('pt')]
        [System.Collections.Hashtable]
        $ParameterTable,
        
        [parameter(Mandatory=$true)]
        [alias('sp')]
        [System.String[]]
        $SpecifiedParameters,

        [parameter(Mandatory=$true)]
        [alias('cp')]
        [System.Collections.Hashtable]
        $CurrentParameters
    )

    $CommonParameters = @('Ensure', 'PIDataArchive')
    $ParametersToPreserve = $CurrentParameters
    # Explicitly specified parameters and common parameters should not be preserved.
    $ParametersToDefer = $SpecifiedParameters + $CommonParameters 
    Foreach($Parameter in $ParametersToDefer)
    { 
       Write-Verbose "NotPreserving: $($Parameter)"
       $null = $ParametersToPreserve.Remove($Parameter)
    }
    # Set the parameter values we want to keep to the current resource values.
    Foreach($Parameter in $ParametersToPreserve.GetEnumerator())
    {
        Write-Verbose "Preserving: $($Parameter.Key): $($Parameter.Value)"
        $ParameterTable[$Parameter.Key] = $Parameter.Value
    }

    return $ParameterTable
}

function IsNullOrEmpty
{
param(
    [Object]
    $Value
)

    return $($null -eq $Value -or "" -eq $Value)
}

Export-ModuleMember -Function @( 'Get-PIResource_Ensure', 'Compare-PIDataArchiveACL', 'Compare-PIResourceGenericProperties', 'Set-PIResourceParametersPreserved', 'IsNullOrEmpty' )