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

.\PIWebAPI_1.10.0_SecurityBaseline -PIWebAPINodeName "myPIWebAPI" -AFServer "myAFServer" -PIWebAPIConfigElementPath "Configuration\OSIsoft\PI Web API\myPIWebAPI\System Configuration" -CorsOrigins "https://myPIWebAPI,https://myPIWebAPI.domain.int"

#>

Configuration PIWebAPI_1.10.0_SecurityBaseline
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

PIWebAPI_1.10.0_SecurityBaseline -PIWebAPINodeName $PIWebAPINodeName `
    -AFServer $AFServer `
    -PIWebAPIConfigElementPath $PIWebAPIConfigElementPath `
    -CorsOrigins $CorsOrigins
