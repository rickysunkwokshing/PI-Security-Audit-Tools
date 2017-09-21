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
            Write-Verbose "GetResult: $($Property): $($PIResource.$Property)."
        }
    }
    return $Ensure
}

Export-ModuleMember -Function @( 'Get-PIResource_Ensure' )