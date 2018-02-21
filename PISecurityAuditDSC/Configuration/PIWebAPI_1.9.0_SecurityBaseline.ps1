<#

.SYNOPSIS

This example configuration covers a baseline configuration for the PI Web API
2017 (1.9.0) to follow best security practices.

.DESCRIPTION

This configuration sets the security-related attributes on the PI Web API 
configuration element.

.PARAMETER NodeName

Name of the PI Web API server.

.PARAMETER PIWebAPIConfigElementPath

Full element path to the PI Web API "System Configuration" config element on 
the PI AF Server.

.PARAMETER CorsOrigins

Allowable origins from which CORS requests will be allowed, separated by commas. 
This should include the domain names of any other sites which will make requests
to the PI Web API.

.EXAMPLE

.\PIWebAPI_1.9.0_SecurityBaseline -PIWebAPINodeName "myPIWebAPI" -AFServer "myAF" -PIWebAPIConfigElementPath "Configuration\OSIsoft\PI Web API\myPIWebAPI\System Configuration" -CorsOrigins "https://myPIWebAPI,https://myPIWebAPI.domain.int"

#>

Configuration PIWebAPI_1.9.0_SecurityBaseline
{
    param
    (
        [parameter(Mandatory=$true)]
        [string]
        $PIWebAPINodeName,

        [parameter(Mandatory=$true)]
        [string]
        $AFServer,

        [parameter(Mandatory=$true)]
        [string]
        $PIWebAPIConfigElementPath,

        [parameter(Mandatory=$true)]
        [string]
        $CorsOrigins
    )

    Import-DscResource -ModuleName PISecurityDSC

    $configAttributes = @(
        @{ 
            Name='AuthenticationMethods'; 
            Type='String'; 
            IsArray=$true; 
            Value=@('Kerberos') 
        },
        @{
            Name='CorsExposedHeaders';
            Type='String';
            IsArray=$false;
            Value='Allow,Content-Encoding,Content-Length,Date,Location';
        },
        @{
            Name='CorsHeaders';
            Type='String';
            IsArray=$false;
            Value='content-type,requestverificationtoken,x-requested-with';
        },
        @{
            Name='CorsMethods';
            Type='String';
            IsArray=$false;
            Value='GET,OPTIONS,POST';
        },
        @{
            Name='CorsOrigins';
            Type='String';
            IsArray=$false;
            Value=$CorsOrigins;
        },
        @{
            Name='XFrameOptions';
            Type='String';
            IsArray=$false;
            Value='SAMEORIGIN';
        },
        @{
            Name='CorsSupportsCredentials';
            Type='Boolean';
            IsArray=$false;
            Value='True';
        },
        @{
            Name='DisableWrites';
            Type='Boolean';
            IsArray=$false;
            Value='False';
        },
        @{
            Name='EnableCSRFDefense';
            Type='Boolean';
            IsArray=$false;
            Value='True';
        }
    )

    Node $PIWebAPINodeName
    {
        foreach($attribute in $configAttributes.GetEnumerator())
        {
            if($null -ne $attribute.Value)
            {
                AFAttribute $attribute.Name
                {
                    AFServer = $AFServer
                    ElementPath = $PIWebAPIConfigElementPath
                    Name = $attribute.Name
                    Type = $attribute.Type
                    IsArray = $attribute.IsArray
                    Value = $attribute.Value
                    Ensure = 'Present'
                }
            }
        }
    }
}

PIWebAPI_1.9.0_SecurityBaseline -PIWebAPINodeName $PIWebAPINodeName `
    -AFServer $AFServer `
    -PIWebAPIConfigElementPath $PIWebAPIConfigElementPath `
    -CorsOrigins $CorsOrigins