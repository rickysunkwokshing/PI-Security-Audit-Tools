function Get-PIResource_Ensure
{
    param(
        [parameter(Mandatory = $true)]
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
        $DesiredSecurity,
        
        [parameter(Mandatory=$true)]
        [System.String]
        $CurrentSecurity
    )
    
    return $($(Compare-Object -ReferenceObject $DesiredSecurity.Split('|').Trim() -DifferenceObject $CurrentSecurity.Split('|').Trim()).Length -eq 0)
}

Export-ModuleMember -Function @( 'Get-PIResource_Ensure', 'Compare-PIDataArchiveACL' )