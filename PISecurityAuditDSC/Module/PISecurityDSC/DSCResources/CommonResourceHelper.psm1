﻿function Get-PIResource_Ensure
{
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
            Write-Verbose "GetResult: $($Property): $($PIResource.$Property.ToString())."
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
    
    return $($(Compare-Object -ReferenceObject $Desired.Split('|').Trim() -DifferenceObject $Current.Split('|').Trim()).Length -eq 0)
}

Export-ModuleMember -Function @( 'Get-PIResource_Ensure', 'Compare-PIDataArchiveACL' )