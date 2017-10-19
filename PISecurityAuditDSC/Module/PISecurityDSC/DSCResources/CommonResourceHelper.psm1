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

function IsNullOrEmpty
{
param(
    [Object]
    $Value
)

    return $($null -eq $Value -or "" -eq $Value)
}

Export-ModuleMember -Function @( 'Get-PIResource_Ensure', 'Compare-PIDataArchiveACL', 'Compare-PIResourceGenericProperties', 'IsNullOrEmpty' )