<#

.SYNOPSIS

This example configuration covers a baseline configuration for the PI Web API
2017 R2 (1.10.0) to follow best security practices.

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

.\PIWebAPI_1.10.0_SecurityBaseline -NodeName "myPIWebAPI" -PIWebAPIConfigElementPath "\\myAF\Configuration\OSIsoft\PI Web API\myPIWebAPI\System Configuration" -CorsOrigins "https://myPIWebAPI,https://myPIWebAPI.domain.int"

#>
param
(
    [parameter(Mandatory=$true)]
    [string]
    $NodeName,

    [parameter(Mandatory=$true)]
    [string]
    $PIWebAPIConfigElementPath,

    [parameter(Mandatory=$true)]
    [string]
    $CorsOrigins
)


Configuration PIWebAPI_1.10.0_SecurityBaseline
{
    param
    (
        [parameter(Mandatory=$true)]
        [string]
        $NodeName,

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
        },
        @{
            Name='CustomHeadersEnabled';
            Type='Boolean';
            IsArray=$false;
            Value='True';
        },
        @{
            Name='CustomHeaders';
            Type='String';
            IsArray=$true;
            Value=@(
                "Content-Security-Policy: frame-ancestors 'self'; object-src 'none'; script-src 'self' 'unsafe-inline'; default-src 'self' 'unsafe-inline'",
                "X-XSS-Protection: 1; mode=block",
                "X-Content-Type-Options: nosniff",
                "Referrer-Policy: same-origin",
                "Strict-Transport-Security: max-age=2592000"
            );
        }
    )

    Node $NodeName
    {
        foreach($attribute in $configAttributes.GetEnumerator())
        {
            if($null -ne $attribute.Value)
            {
                AFAttribute $attribute.Name
                {
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

PIWebAPI_1.10.0_SecurityBaseline -NodeName $NodeName `
    -PIWebAPIConfigElementPath $PIWebAPIConfigElementPath `
    -CorsOrigins $CorsOrigins
