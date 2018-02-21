function ConvertFrom-TypeString
{
    [cmdletbinding()]
    param
    (
        [ValidateSet("Boolean", "Byte", "DateTime", "Double", "Int16", "Int32", "Int64", "Single", "String")]
        [string]$TypeName,

        [boolean]$IsArray
    )

    if($IsArray)
    {
        switch($TypeName)
        {
            "Boolean" {[System.Boolean[]]; break}
            "Byte" {[System.Byte[]]; break}
            "DateTime" {[System.DateTime[]]; break}
            "Double" {[System.Double[]]; break}
            "Int16" {[System.Int16[]]; break}
            "Int32" {[System.Int32[]]; break}
            "Int64" {[System.Int64[]]; break}
            "Single" {[System.Single[]]; break}
            "String" {[System.String[]]; break}
        }
    }
    else
    {
        switch($TypeName)
        {
            "Boolean" {[System.Boolean]; break}
            "Byte" {[System.Byte]; break}
            "DateTime" {[System.DateTime]; break}
            "Double" {[System.Double]; break}
            "Int16" {[System.Int16]; break}
            "Int32" {[System.Int32]; break}
            "Int64" {[System.Int64]; break}
            "Single" {[System.Single]; break}
            "String" {[System.String]; break}
        }
    }
}

function ConvertTo-FullPath
{
param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AFServer,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ElementPath
)

$FullPath = "\\" + $AFServer.Trim("\") + "\" + $ElementPath.Trim("\")

return $FullPath
}

function Get-TargetResource
{
    [cmdletbinding()]
    param
    (
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AFServer,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ElementPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [string[]]$Value,

        [ValidateSet("Boolean", "Byte", "DateTime", "Double", "Int16", "Int32", "Int64", "Single", "String")]
        [string]$Type = "String",

        [boolean]$IsArray = $false
    )

    $getTargetResourceResult = $null
    $ensureResult = $null
    $attributeName = $null
    $attributeValue = $null
    $attributeType = $null
    $attributeIsArray = $null

    $ElementPath = ConvertTo-FullPath -AFServer $AFServer -ElementPath $ElementPath
    # Load AF SDK. Calling this while it's already loaded shouldn't be harmful
    $loaded = [System.Reflection.Assembly]::LoadWithPartialName("OSIsoft.AFSDK")
    if ($null -eq $loaded) {
        $ErrorActionPreference = 'Stop'
        throw "AF SDK could not be loaded"
    }

    $tempList = New-Object "System.Collections.Generic.List[string]"
    $tempList.Add($ElementPath) | Out-Null

    # This method returns a collection, must find specific element using key of the path
    $element = [OSIsoft.AF.Asset.AFElement]::FindElementsByPath($tempList, $null)[$ElementPath]
    if($null -eq $element)
    {
        $ErrorActionPreference = 'Stop'
        throw "Could not locate AF Element at path $ElementPath"
    }

    $attribute = $element.Attributes | Where-Object Name -EQ $Name
    if($null -eq $attribute)
    {
        $ensureResult = 'Absent'
    }
    else
    {
        $ensureResult = 'Present'
        $attributeName = $attribute.Name
        $attributeValue = $attribute.GetValue().Value
        $attributeType = $attribute.Type.Name -replace '\[\]', ''
        $attributeIsArray = $attribute.Type.Name.EndsWith('[]')
    }

    $getTargetResourceResult = @{
                                    Name = $attributeName;
                                    Ensure = $ensureResult;
                                    ElementPath = $ElementPath;
                                    Value = $attributeValue;
                                    Type = $attributeType;
                                    IsArray = $attributeIsArray;
                                }

    Write-Verbose "GetResult: Name: $Name"
    Write-Verbose "GetResult: ElementPath: $ElementPath"
    Write-Verbose "GetResult: EnsureResult: $ensureResult"
    Write-Verbose "GetResult: Value: $attributeValue"
    Write-Verbose "GetResult: Type: $attributeType"
    Write-Verbose "GetResult: IsArray: $attributeIsArray"

    $getTargetResourceResult
}


function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AFServer,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ElementPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [string[]]$Value,

        [ValidateSet("Boolean", "Byte", "DateTime", "Double", "Int16", "Int32", "Int64", "Single", "String")]
        [string]$Type = "String",

        [boolean]$IsArray = $false
    )

    $ElementPath = ConvertTo-FullPath -AFServer $AFServer -ElementPath $ElementPath
    # Load AF SDK. Calling this while it's already loaded by PowerShell tools shouldn't be harmful
    $loaded = [System.Reflection.Assembly]::LoadWithPartialName("OSIsoft.AFSDK")
    if ($null -eq $loaded) {
        $ErrorActionPreference = 'Stop'
        throw "AF SDK could not be loaded"
    }

    $tempList = New-Object "System.Collections.Generic.List[string]"
    $tempList.Add($ElementPath) | Out-Null

    # This method returns a collection, must find specific element using key of the path
    $element = [OSIsoft.AF.Asset.AFElement]::FindElementsByPath($tempList, $null)[$ElementPath]
    if($null -eq $element)
    {
        $ErrorActionPreference = 'Stop'
        throw "Could not locate AF Element at path $ElementPath"
    }
    Write-Verbose "Found Element at $ElementPath"

    $attribute = $element.Attributes | Where-Object Name -EQ $Name

    if($null -eq $attribute) 
    # Attribute missing
    {
        Write-Verbose "Attribute '$Name' not found in Element"
        if($Ensure -eq 'Absent') { return }
        else 
        # Need to create attribute
        {
            Write-Verbose "Creating attribute Name: '$Name' Value: $Value"
            $attribute = $element.Attributes.Add($Name)
            $attribute.Type = ConvertFrom-TypeString -TypeName $Type -IsArray $IsArray
            if($IsArray)
            {
                $attribute.SetValue($Value) # writes array
            }
            else
            {
                $attribute.SetValue($Value[0])
            }
            $element.CheckIn()
        }
    }
    else
    # Attribute present
    {
        Write-Verbose "Attribute '$Name' found in Element"
        if($Ensure -eq 'Absent')
        # Need to delete attribute
        {
            Write-Verbose "Deleting attribute Name: '$Name'"
            $element.Attributes.Remove($attribute.Name) | Out-Null
            $element.CheckIn()
        }
        else
        # Update attribute type and value if not matching
        {
            Write-Verbose "Type: $($attribute.Type.Name)"
            Write-Verbose "Value: $($attribute.GetValue().Value)"
            $typeMatch = $attribute.Type -eq (ConvertFrom-TypeString -TypeName $Type -IsArray $IsArray)
            if(-not $typeMatch)
            {
                Write-Verbose "Setting type to $Type$(if($IsArray){'[]'})" 
                $attribute.Type = ConvertFrom-TypeString -TypeName $Type -IsArray $IsArray
            }
            if($IsArray)
            {
                # Array equality check is a pain, here's the workaround
                if($result.Value.Count -ne $Value.Count)
                {
                    $valueMatch = $false
                }
                else
                {
                    $valueMatch = $true
                    for($i=0; $i -lt $result.Value.Count; $i++)
                    {
                        if(([string]$result.Value[$i]) -ne $Value[$i]) { $valueMatch = $false }
                    }
                }
                if(-not $valueMatch)
                {
                    Write-Verbose "Setting value to $($Value -join ',')"
                    $attribute.SetValue($Value)
                    $element.CheckIn()
                }
            }
            else
            {
                if($attribute.GetValue().Value -ne $Value[0])
                {
                    Write-Verbose "Setting value to $($Value[0])"
                    $attribute.SetValue($Value[0])
                    $element.CheckIn()
                }
            }
        }
    }
}


function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$AFServer,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ElementPath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [string[]]$Value,

        [ValidateSet("Boolean", "Byte", "DateTime", "Double", "Int16", "Int32", "Int64", "Single", "String")]
        [string]$Type = "String",

        [boolean]$IsArray = $false
    )

    $result = Get-TargetResource -Ensure Present -ElementPath $ElementPath -Name $Name -AFServer $AFServer
    $ensureMatch = $result.Ensure -eq $Ensure
    $typeMatch = $result.Type -eq $Type
    $arrayMatch = $result.IsArray -eq $IsArray
    if($result.IsArray)
    {
        # Array equality check is a pain, here's the workaround
        if($result.Value.Count -ne $Value.Count)
        {
            $valueMatch = $false
        }
        else
        {
            $valueMatch = $true
            for($i=0; $i -lt $result.Value.Count; $i++)
            {
                if(([string]$result.Value[$i]) -ne $Value[$i]) { $valueMatch = $false }
            }
        }
    }
    else
    {
        $valueMatch = [string]$result.Value -eq $Value
    }

    Write-Verbose "TestResult: Ensure: $ensureMatch"
    Write-Verbose "TestResult: Value: $valueMatch"
    Write-Verbose "TestResult: Type: $typeMatch"
    Write-Verbose "TestResult: IsArray: $arrayMatch"

    if($ensureMatch -and $valueMatch -and $typeMatch -and $arrayMatch)
    {
        $true
    }
    else
    {
        $false
    }
}

Export-ModuleMember -Function *-TargetResource