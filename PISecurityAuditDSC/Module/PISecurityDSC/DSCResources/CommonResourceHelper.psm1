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

function Convert-PISecurityStringToHashTable
{
    param(
        [parameter(Mandatory=$true)]
        [System.String]
        $SecurityString
    )
    [Hashtable]$SecurityTable = @{}
    # Break pipe delimited ACL into entries
    # Entry format: <Identity>: A(<Read, Write or 0>)
    # Example: 'piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)'
    $SecurityEntries = $SecurityString.Split('|').Trim()

    # Construct the desired security hashtable
    foreach($Entry in $SecurityEntries)
    {
        # Split entry into the identity and access
        $tokens = $Entry.Split(':').Trim()
        # Assign accordingly
        $Identity = $tokens[0]
        $AccessRaw = $tokens[1]
        # Convert the access to the same format as the current state representation.
        switch ($AccessRaw)
        {
            'A(r,w)' {$Access = 'Read, Write';break}
            'A(r)' {$Access = 'Read';break}
            'A(w)' {$Access = 'Write';break}
            'A()' {$Access = 0;break}
        }
        $SecurityTable.Add($Identity,$Access)
    }
    return $SecurityTable
}

Export-ModuleMember -Function @( 'Get-PIResource_Ensure', 'Convert-PISecurityStringToHashTable' )