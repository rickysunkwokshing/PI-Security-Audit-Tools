function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."


    <#
    $returnValue = @{
    PrincipalName = [System.String]
    Description = [System.String]
    PIDataArchive = [System.String]
    Ensure = [System.String]
    Disabled = [System.Boolean]
    Name = [System.String]
    Identity = [System.String]
    }

    $returnValue
    #>
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [System.String]
        $PrincipalName,

        [System.String]
        $Description,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Boolean]
        $Disabled,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.String]
        $Identity
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."

    #Include this line if the resource requires a system reboot.
    #$global:DSCMachineStatus = 1


}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [System.String]
        $PrincipalName,

        [System.String]
        $Description,

        [parameter(Mandatory = $true)]
        [System.String]
        $PIDataArchive,

        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [System.Boolean]
        $Disabled,

        [parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [System.String]
        $Identity
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."


    <#
    $result = [System.Boolean]
    
    $result
    #>
}


Export-ModuleMember -Function *-TargetResource

