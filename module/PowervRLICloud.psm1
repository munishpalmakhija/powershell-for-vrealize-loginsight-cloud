#Author - Munishpal Makhija

#    ===========================================================================
#    Created by:    Munishpal Makhija
#    Release Date:  10/12/2022
#    Organization:  VMware
#    Version:       1.0
#    Blog:          https://munishpalmakhija.com
#    Twitter:       @munishpal_singh
#    ===========================================================================


####################### Get-vRLI-CloudCommands ######################### 

function Get-vRLI-CloudCommands {
<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all cmdlets for vRLI Cloud
    .DESCRIPTION
        This cmdlet will allow you to return all cmdlets included in the Power vRLI Cloud Module
    .EXAMPLE
        Get-vRLI-CloudCommands
    .EXAMPLE
        Get-Command -Module PowervRLICloud
    .NOTES
        You can either use this cmdlet or the Get-Command cmdlet as seen in Example 2
#>
    Get-Command -Module PowervRLICloud

}

####################### Connect-vRLI-Cloud ######################### 

function Connect-vRLI-Cloud
{
<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Connects to vRLI Cloud and gets CSP Access Token to be used with APIs 
    .DESCRIPTION
        This cmdlet creates $global:defaultvRLICConnection object
    .EXAMPLE
        Connect-vRLI-Cloud -APIToken $APIToken
        Input APIToken as Secure String by using Read-Host "$APIToken = Read-Host -AsSecureString"            
#>
    param (
    [Parameter (Mandatory=$true)]
      # vRLI Cloud API Token
      [ValidateNotNullOrEmpty()]
      [Security.SecureString]$APIToken,
      [Parameter (Mandatory=$False)]
        # Deployment Name
        [ValidateNotNullOrEmpty()]
        [String]$Region="us"      
  )  
  if (($PSVersionTable.PSVersion.Major -eq 6)) {
     $API = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($APIToken)) 
  }
  elseif (($PSVersionTable.PSVersion.Major -eq 7)) {
     $API = ConvertFrom-SecureString -SecureString $APIToken -AsPlainText
  }
  $csp_host = "console.cloud.vmware.com"  
  $url = "https://$csp_host/csp/gateway/am/api/auth/api-tokens/authorize?source=PowervRLICloud"
  $headers = @{"Accept"="application/json";
 "Content-Type"="application/x-www-form-urlencoded";
}
$payload = @{"refresh_token"=$API;}
#$body= $payload | Convertto-Json
$response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $payload -ErrorAction:Stop
  if($response)
  {
    #$response = ($response | ConvertFrom-Json)
    function Get-JWTDetails {
        [cmdletbinding()]
        param(
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
            [string]$token
        )
        if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

        # Token
        foreach ($i in 0..1) {
            $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
            switch ($data.Length % 4) {
                0 { break }
                2 { $data += '==' }
                3 { $data += '=' }
            }
        }
        $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json 
        Write-Verbose "JWT Token:"
        Write-Verbose $decodedToken
        # Signature
        foreach ($i in 0..2) {
            $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
            switch ($sig.Length % 4) {
                0 { break }
                2 { $sig += '==' }
                3 { $sig += '=' }
            }
        }
        Write-Verbose "JWT Signature:"
        Write-Verbose $sig
        $decodedToken | Add-Member -Type NoteProperty -Name "sig" -Value $sig

        # Convert Expiry time to PowerShell DateTime
        $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
        $timeZone = Get-TimeZone
        $utcTime = $orig.AddSeconds($decodedToken.exp)
        $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
        $localTime = $utcTime.AddMinutes($offset)     # Return local time,              
        $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $localTime
                
        # Time to Expiry
        $timeToExpiry = ($localTime - (get-date))
        $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry

        return $decodedToken
    }
  $token = $response.access_token
  $results = Get-JWTDetails($token)

    #$sd = ($results.perms | grep -i "log-intelligence").Split("/")[1]
    $sd = (($results.perms | Select-String -Pattern "log-intelligence").Line).Split("/")[1]
    #$si = (($results.perms | grep -i "log-intelligence").Split(":")[1]).Split("/")[0]
    $si = ((($results.perms | Select-String -Pattern "log-intelligence").Line).Split(":")[1]).Split("/")[0]
    
    $org_id = $results.context_name

    if ($Region -eq "us")
    {
      $apiurl = "api.mgmt.cloud.vmware.com"
      $dataurl = "data.mgmt.cloud.vmware.com"
    }
    else
    {
        $apiurl = $Region + ".api.mgmt.cloud.vmware.com"
        $dataurl = $Region + "data.mgmt.cloud.vmware.com"
    }    
    # Setup a custom object to contain the parameters of the connection, including the URL to the CSP API & Access token
    $connection = [pscustomObject] @{
      "Server" = $apiurl      
      "CSPToken" = $response.access_token
      "DataURL" = $dataurl
      "OrgId" = $org_id
      "ServiceId" = $sd
      "ServiceInstance" = $si
      "CSPHost" = $csp_host
    }

    # Remember this as the default connection
    Set-Variable -name defaultvRLICConnection -value $connection -scope Global

    # Return the connection
    $connection
  }
}

####################### Disconnect-vRLI-Cloud ######################### 

function Disconnect-vRLI-Cloud
{
<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Destroys $global:defaultvRLICConnection object if it exists
    .DESCRIPTION
        REST is not connection oriented, so there really isnt a connect/disconnect concept. It destroys $global:defaultvRLICConnection object if it exists
    .EXAMPLE
        Disconnect-vRLI-Cloud                  
#>
    if (Get-Variable -Name defaultvRLICConnection -scope global ) {
        Remove-Variable -name defaultvRLICConnection -scope global
    }
}


######################### Get-AlertDefinitions #########################

function Get-AlertDefinitions
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Alert Definitions in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Alert Definitions in a particular Org 
    .EXAMPLE
        Get-AlertDefinitions | where{$_.name -match "Test"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection     
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/alert"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Alert Definitions"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Remove-AlertDefinition #########################

function Remove-AlertDefinition
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Deletes vRLIC Alert Definition in a particular Org 
    .DESCRIPTION
        This cmdlet deletes vRLIC Alert Definition in a particular Org 
    .EXAMPLE
        Remove-AlertDefinition -AlertName "Test"
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Alert Definition Name
        [ValidateNotNullOrEmpty()]
        [string]$AlertName           
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $r = Get-AlertDefinitions | where{$_.name -eq $AlertName}
            $vrlic_uri = "/vrlic/api/v1/alert/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ $r.id+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method DELETE -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in deleting vRLIC Alert Definitions"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-AlertInstanceById #########################

function Get-AlertInstanceById
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Alert Instance in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Alert Instance in a particular Org 
    .EXAMPLE
        Get-AlertInstanceById -Id "xxx444"
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Alert Instance ID
        [ValidateNotNullOrEmpty()]
        [string]$Id              
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/alert/instances/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ $Id+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Alert Instances"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-AlertInstances #########################

function Get-AlertInstances
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC all Alert Instances in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC all Alert Instances in a particular Org 
    .EXAMPLE
        Get-AlertInstances -Duration 60
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
      # Duration in Mins
      [ValidateNotNullOrEmpty()]
      [string]$Duration                
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/alert/instances/query"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ $Id+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $end=get-date
            $start=$end.AddMinutes(-$Duration)
            $start_ms=([DateTimeOffset]$start).ToUnixTimeMilliseconds()
            $end_ms=([DateTimeOffset]$end).ToUnixTimeMilliseconds()
            $vrlic_body = "{`n `"namespace`": `"com.vmware.li`",`n `"resultLimit`": 500,`n `"startTime`": $start_ms,`n `"endTime`": $end_ms`n}"               
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $nextpage = $response.nextPageLink

            $body = "{`n    `"resultLimit`": 500,`n    `"nextPageLink`": `"$nextpage`"    `n}"
            $r = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $r.alertInstanceColl
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Alert Instances"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-ContentPack-Dashboards #########################

function Get-ContentPack-Dashboards
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Content Pack Dashboards in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Content Pack Dashboards in a particular Org 
    .EXAMPLE
        Get-ContentPack-Dashboards | where{$_.name -match "Test"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection     
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/content/dashboards/CONTENT_PACK"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.dashboards       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Content Pack Dashboards"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-Favourite-Dashboards #########################

function Get-Favourite-Dashboards
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Favourite Dashboards in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Favourite Dashboards in a particular Org 
    .EXAMPLE
        Get-ContentPack-Dashboards | where{$_.name -match "Test"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection     
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/content/dashboards/favourites"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.dashboards       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Favourite Dashboards"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-Userdefined-Dashboards #########################

function Get-Userdefined-Dashboards
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC User Defined Dashboards in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC User Defined Dashboards in a particular Org 
    .EXAMPLE
        Get-Userdefined-Dashboards | where{$_.name -match "Test"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection     
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/content/dashboards/USER_DEFINED"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.dashboards       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC User Defined Dashboards"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Post-Query-Request #########################

function Post-Query-Request
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Creates a log query in a particular Org 
    .DESCRIPTION
        This cmdlet creates a log query in a particular Org 
    .EXAMPLE
        Post-Query-Request -SQlQuery "SELECT * FROM logs ORDER BY ingest_timestamp DESC" -Duration 60  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # SQL Query
        [ValidateNotNullOrEmpty()]
        [string]$SQLQuery,
        [Parameter (Mandatory=$true)]
        # Duration in Mins
        [ValidateNotNullOrEmpty()]
        [string]$Duration                      
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/query/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $end=get-date
            $start=$end.AddMinutes(-$Duration)
            $start_ms=([DateTimeOffset]$start).ToUnixTimeMilliseconds()
            $end_ms=([DateTimeOffset]$end).ToUnixTimeMilliseconds()
            $vrlic_body = "{`n    `"logQuery`": `"$SQLQuery`",`n    `"start`": $start_ms,`n    `"end`": $end_ms`n}   "               
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.id       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in posting vRLIC query request"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-QueryResponse #########################

function Get-QueryResponse
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC gets a log query by id in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC log query by id in a particular Org 
    .EXAMPLE
        Get-QueryResponse  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Query ID
        [ValidateNotNullOrEmpty()]
        [string]$QueryId         
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/query/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ $QueryId+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer validGet-Date, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Log Query"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-Roles #########################

function Get-Roles
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC roles in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC roles in a particular Org 
    .EXAMPLE
        Get-Roles | where{$_.name -match "Test"}   
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection    
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/access-control/role"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Roles"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-CurrentRole #########################

function Get-CurrentRole
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC current role in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC current role in a particular Org 
    .EXAMPLE
        Get-CurrentRole  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection    
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/access-control/role/current"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Current Role"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-Datasets #########################

function Get-Datasets
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC roles in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC roles in a particular Org 
    .EXAMPLE
        Get-Datasets | where{$_.name -match "Test"}   
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection    
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/access-control/dataset"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Datasets"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-CurrentDataset #########################

function Get-CurrentDataset
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC current dataset in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC current dataset in a particular Org 
    .EXAMPLE
        Get-CurrentDataset 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection    
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/access-control/dataset/current"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Current Dataset"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Create-AccessKey #########################

function Create-AccessKey
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Creates vRLIC Access Key in a particular Org 
    .DESCRIPTION
        This cmdlet creates vRLIC Access Key in a particular Org 
    .EXAMPLE
        Create-AccessKey -KeyName "MMTest"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Key Name
        [ValidateNotNullOrEmpty()]
        [string]$KeyName            
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/resources/access-keys"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $vrlic_body = "{`n    `"name`": `"$KeyName`"`n}"            
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in creating vRLIC Access Keys "
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-AccessKey #########################

function Get-AccessKey
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Access Key details in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Access Key details in a particular Org 
    .EXAMPLE
        Get-AccessKey -KeyName "MMTest"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Name
        [ValidateNotNullOrEmpty()]
        [string]$KeyName            
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $r=Get-CurrentDataset
            $keyId= $r.cspOrgId+ "-"+ $KeyName+ "?source=PowervRLICloud"
            $vrlic_uri = "/vrlic/api/v1/resources/access-keys/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ $keyId
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Access Keys "
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Remove-AccessKey #########################

function Remove-AccessKey
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Deletes vRLIC Access Key in a particular Org 
    .DESCRIPTION
        This cmdlet deletes vRLIC Access Key in a particular Org 
    .EXAMPLE
        Remove-AccessKey -Name "MMTest"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Key Name
        [ValidateNotNullOrEmpty()]
        [string]$KeyName            
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $r=Get-CurrentDataset
            $keyId= $r.cspOrgId+ "-"+ $KeyName+ "?source=PowervRLICloud"
            $vrlic_uri = "/vrlic/api/v1/resources/access-keys/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ $keyId
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method DELETE -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            if ($response){
                Write-Host -ForegroundColor Green "Access Key removed successfully" 
                break
            }      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in deleting vRLIC Access Key "
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-SubscriptionStatus #########################

function Get-SubscriptionStatus
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Subscription Status in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Subscription Status in a particular Org 
    .EXAMPLE
        Get-SubscriptionStatus | where{$_.name -match "Test"}   
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection    
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/subscriptions/status"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.usage      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Subscription Status"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-UsageReport #########################

function Get-UsageReport
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Usage Report in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Usage Report in a particular Org 
    .EXAMPLE
        Get-UsageReport -UsageType DATA_INGESTED_BILLABLE_V2 -Duration 1440  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Usage Type
        [ValidateNotNullOrEmpty()]
        [string]$UsageType,
      [Parameter (Mandatory=$false)]
        # Duration in Mins
        [ValidateNotNullOrEmpty()]
        [string]$Duration=8                             
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/billing/usage-reports"
            $url = $Connection.Server
            $usage_type=$UsageType
            $end=get-date
            $start=$end.AddMinutes(-$Duration)
            $start_ms=([DateTimeOffset]$start).ToUnixTimeMilliseconds()
            $end_ms=([DateTimeOffset]$end).ToUnixTimeMilliseconds()            
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?usageType="+ $usage_type+ "&start="+ $start_ms+ "&end="+ $end_ms
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.usage.$usage_type  
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Usage Report"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Post-LogsTovRLICloud #########################

function Post-LogsTovRLICloud
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Ingest log message in a particular Org 
    .DESCRIPTION
        This cmdlet ingests log message in a particular Org 
    .EXAMPLE
        Post-LogsTovRLICloud -AccessKeyName $AccessKeyName -LogMessage $LogMessage 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Access Key Name
        [ValidateNotNullOrEmpty()]
        [string]$AccessKeyName,
        [Parameter (Mandatory=$true)]
        # Log Message
        [ValidateNotNullOrEmpty()]
        [string]$LogMessage                      
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/le-mans/v1/streams/ingestion-pipeline-stream"
            $url = $Connection.DataURL
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $AccessKey = Get-AccessKey -KeyName $AccessKeyName
            $cspauthtoken= $AccessKey.key
            $hostname = hostname
            $d=get-date
            $log_timestamp=([DateTimeOffset]$d).ToUnixTimeMilliseconds()         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $vrlic_body = "[`n	{`n		`"text`": `"$LogMessage`"`n		`"source_hostname`": `"$hostname`"`n   `"log_source`": `"powervrlicloud`"`n        `"log_timestamp`": `"$log_timestamp`"`n	}`n]	"              
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error senging logs to vRLI Cloud"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Post-LogsToCloudProxy #########################

function Post-LogsToCloudProxy
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Ingest log message in a particular Org via Cloud Proxy 
    .DESCRIPTION
        This cmdlet ingests log message in a particular Org via Cloud Proxy 
    .EXAMPLE
        Post-LogsToCloudProxy -CloudProxyIP $CloudProxyIP -LogMessage $LogMessage  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Cloud Proxy IP
        [ValidateNotNullOrEmpty()]
        [string]$CloudProxyIP,
        [Parameter (Mandatory=$true)]
        # Log Message
        [ValidateNotNullOrEmpty()]
        [string]$LogMessage                             
  )
    $vrlic_uri = ":9000/log-forwarder/ingest"
    $vrlic_url = "http://"+ $CloudProxyIP+ $vrlic_uri+ "?source=PowervRLICloud"
    $hostname = hostname
    $d=get-date
    $log_timestamp=([DateTimeOffset]$d).ToUnixTimeMilliseconds()   

    $vrlic_headers = @{"Accept"="*/*";
    "Content-Type"="application/json"; 
    }
    $vrlic_body = "{`n   `"source_hostname`":   `"$hostname`",`n   `"log_source`": `"powervrlicloud`",`n   `"text`": `"$LogMessage`",`n   `"log_timestamp`": `"$log_timestamp`"`n}"
            
    $response = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
    $response.result    
}
######################### Search-UserInOrg #########################

function Search-UserInOrg
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Search User in a particular Org 
    .DESCRIPTION
        This cmdlet Search User in a particular Org 
    .EXAMPLE
        Search-UserInOrg -UserEmail $UserEmail  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$False)]
        # User Email
        [ValidateNotNullOrEmpty()]
        [string]$UserEmail                         
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            
            $orgId = $Connection.OrgId
            $csp_host = $Connection.CSPHost
            $fullurl = "https://$csp_host/csp/gateway/am/api/v2/users/search"

            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $vrlic_body = "{`n    `"searchTerm`": `"$UserEmail`"`n}"
            $response = Invoke-RestMethod -Uri $fullurl -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.results
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error Searching for the user"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-UserServiceRoles #########################

function Get-UserServiceRoles
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns User Service Roles in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves User Service Roles in a particular Org 
    .EXAMPLE
        Get-UserServiceRoles -UserEmail $UserEmail
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
        [Parameter (Mandatory=$true)]
        # User Email
        [ValidateNotNullOrEmpty()]
        [string]$UserEmail           
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $orgId = $Connection.OrgId
            $u = Search-UserInOrg -UserEmail $UserEmail
            $userid = $u.userId
            $csp_host = $Connection.CSPHost            
            $fullurl = "https://$csp_host/csp/gateway/am/api/v2/users/$userid/orgs/$orgId/service-roles?source=PowervRLICloud"

            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $fullurl -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.serviceRoles.serviceRoles     
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving User Service Roles"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Invite-NewUserTovRLICloudService #########################

function Invite-NewUserTovRLICloudService
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Add/Invite User to vRLI Cloud Service in a particular Org 
    .DESCRIPTION
        This cmdlet Adds/Invites User to vRLI Cloud Service  in a particular Org 
    .EXAMPLE
        Invite-NewUserTovRLICloudService -UserEmail $UserEmail  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$False)]
        # Org Role Name
        [ValidateNotNullOrEmpty()]
        [string]$OrgRoleName = "org_member",
        [Parameter (Mandatory=$true)]
        # User Email
        [ValidateNotNullOrEmpty()]
        [string]$UserEmail,
      [Parameter (Mandatory=$False)]
        # vRLI Cloud Service Role Name
        [ValidateNotNullOrEmpty()]
        [string]$ServiceRoleName = "log-intelligence:user"                          
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            
            $orgId = $Connection.OrgId
            $csp_host = $Connection.CSPHost
            $fullurl = "https://$csp_host/csp/gateway/am/api/orgs/$orgId/invitations"

            $sd = $Connection.ServiceId
            $id = $Connection.ServiceInstance
            $instanceid = "instance:"+ $id

            $serviceDefinition = "/csp/gateway/slc/api/definitions/external/"+ $sd 

            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }

            $vrlic_body = "{`n    `"skipNotify`": false,`n    `"usernames`": [`n        `"$UserEmail`"`n    ],`n    `"organizationRoles`": [`n        {`n            `"name`": `"$OrgRoleName`",`n            `"expiresAt`": null`n        }`n    ],`n    `"serviceRolesDtos`": [`n        {`n            `"serviceRoles`": [`n                {`n                    `"name`": `"$ServiceRoleName`",`n                    `"expiresAt`": null,`n                    `"resource`": `"$instanceid`"`n                 }`n            ],`n            `"serviceDefinitionLink`": `"$serviceDefinition`"`n        }`n    ]`n}"
             
            $response = Invoke-RestMethod -Uri $fullurl -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck

            $response       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error inviting New User to vRLI Cloud"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}
######################### Add-UserTovRLICloudService #########################

function Add-UserTovRLICloudService
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Add's User to vRLI Cloud Service in a particular Org 
    .DESCRIPTION
        This cmdlet Add's User to vRLI Cloud Service in a particular Org 
    .EXAMPLE
        Add-UserTovRLICloudService  -UserEmail $UserEmail
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
        [Parameter (Mandatory=$true)]
        # User Email
        [ValidateNotNullOrEmpty()]
        [string]$UserEmail,
      [Parameter (Mandatory=$False)]
        # vRLI Cloud Service Role Name
        [ValidateNotNullOrEmpty()]
        [string]$ServiceRoleName = "log-intelligence:user"                                 
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            
            $orgId = $Connection.OrgId
            $sd = $Connection.ServiceId
            $id = $Connection.ServiceInstance
            $instanceid = "instance:"+ $id
            $u = Search-UserInOrg -UserEmail $UserEmail
            $userid = $u.userId
            $csp_host = $Connection.CSPHost
            $fullurl = "https://$csp_host/csp/gateway/am/api/v3/users/$userid/orgs/$orgId/roles"

            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }

            $vrlic_body = "{`n    `"serviceRoles`": [`n        {`n            `"serviceDefinitionId`": `"$sd`",`n            `"rolesToAdd`": [`n                {`n                    `"name`": `"$ServiceRoleName`",`n                    `"resource`": `"instance:$id`",`n                    `"membershipType`": `"DIRECT`"`n                }`n            ]`n        }`n    ],`n    `"notifyUsers`": false`n}"
             
            $response = Invoke-RestMethod -Uri $fullurl -Method Patch -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck

            $response       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error Adding User to vRLI Cloud Service"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Remove-UserFromvRLICloudService #########################

function Remove-UserFromvRLICloudService
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Remove User from vRLI Cloud Service in a particular Org 
    .DESCRIPTION
        This cmdlet Remove User from vRLI Cloud Service  in a particular Org 
    .EXAMPLE
        Remove-UserFromvRLICloudService -UserEmail $UserEmail 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
        [Parameter (Mandatory=$true)]
        # User Email
        [ValidateNotNullOrEmpty()]
        [string]$UserEmail                         
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            
            $orgId = $Connection.OrgId
            $sd = $Connection.ServiceId
            $id = $Connection.ServiceInstance
            $instanceid = "instance:"+ $id
            $u = Search-UserInOrg -UserEmail $UserEmail
            $userid = $u.userId
            $roles = Get-UserServiceRoles -UserEmail $UserEmail | where{$_.name -match "log-intelligence"}
            $rolename = $roles.name
            $csp_host = $Connection.CSPHost 
            $fullurl = "https://$csp_host/csp/gateway/am/api/v3/users/$userid/orgs/$orgId/roles"

            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }

            $vrlic_body = "{`n    `"serviceRoles`": [`n        {`n            `"serviceDefinitionId`": `"$sd`",`n            `"rolesToRemove`": [`n                {`n                    `"name`": `"$rolename`",`n                    `"resource`": `"instance:$id`",`n                    `"membershipType`": `"DIRECT`"`n                }`n            ]`n        }`n    ],`n    `"notifyUsers`": false`n}"

            $response = Invoke-RestMethod -Uri $fullurl -Method Patch -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck

            $response       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error Removing User from vRLI Cloud Service"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}
######################### Remove-UserFromOrg #########################

function Remove-UserFromOrg
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          03/13/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Remove User from a particular Org 
    .DESCRIPTION
        This cmdlet Remove User from a particular Org 
    .EXAMPLE
        Remove-UserFromOrg -UserEmail $UserEmail  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
        [Parameter (Mandatory=$true)]
        # User Email
        [ValidateNotNullOrEmpty()]
        [string]$UserEmail                         
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            
            $orgId = $Connection.OrgId
            $u = Search-UserInOrg -UserEmail $UserEmail
            $userid = $u.userId
            $csp_host = $Connection.CSPHost
            $fullurl = "https://$csp_host/csp/gateway/am/api/v2/orgs/$orgId/users"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }

            $vrlic_body = "{`n  `"ids`": [`n        `"$userid`"`n    ]`n}"

            $response = Invoke-RestMethod -Uri $fullurl -Method DELETE -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck

            $response       
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error removing user from Org "
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-Tags #########################

function Get-Tags
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Tags in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Tags in a particular Org 
    .EXAMPLE
        Get-Tags | where{$_.name -match "Test"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$False)]
        # Size
        [ValidateNotNullOrEmpty()]
        [string]$Size=20         
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/tags?size=$Size&sort=asc"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "&source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Tags"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Create-Tag #########################

function Create-Tag
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Creates a tag in a particular Org 
    .DESCRIPTION
        This cmdlet creates a tag in a particular Org 
    .EXAMPLE
        Create-Tag -Name "MMPowervRLICloudTest" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        #Name
        [ValidateNotNullOrEmpty()]
        [string]$Name                     
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/tags/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $vrlic_body = "{
                `"name`": `"$Name`"
            }"               
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response     
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in creating vRLIC Tag"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Remove-Tag #########################

function Remove-Tag
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Deletes vRLIC Tag in a particular Org 
    .DESCRIPTION
        This cmdlet deletes vRLIC Tag in a particular Org 
    .EXAMPLE
        Remove-Tag -Name "MMPowervRLICloudTest"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Name
        [ValidateNotNullOrEmpty()]
        [string]$Name            
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $tag=Get-Tags | where{$_.name -match "$Name"}
            $tagId=$tag.id
            $vrlic_uri = "/vrlic/api/v1/tags/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ $tagId+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method DELETE -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            if ($response){
                Write-Host -ForegroundColor Green "Tag removed successfully" 
                break
            }      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in deleting vRLIC Tag "
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vSphereConfig #########################

function Get-vSphereConfig
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC vSphere configs in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC vSphere configs in a particular Org 
    .EXAMPLE
        Get-vSphereConfig | where{$_.hostname -match "lab.local"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection       
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/vsphere/configs"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC vSphere Configs"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-WebhookConfig #########################

function Get-WebhookConfig
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Webhook Config in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Webhook Config in a particular Org 
    .EXAMPLE
        Get-WebhookConfig | where{$_.name -match "Test"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection       
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/notification/webhook-configurations"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Webhook Configs"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}
######################### Get-Fields #########################

function Get-Fields
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Fields in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Fields in a particular Org 
    .EXAMPLE
        Get-Fields | where{$_.displayName -match "test"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$False)]
        # QuerySource
        [ValidateNotNullOrEmpty()]
        [string]$FieldType="LOGS"            
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/query/fields?type=$FieldType"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.fields      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Fields"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Create-QueryDefinition #########################

function Create-QueryDefinition
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Creates an Query Definition in a particular Org 
    .DESCRIPTION
        This cmdlet an Query Definition in a particular Org 
    .EXAMPLE
        $payload = Get-Content ./config.json | ConvertTo-Json
        Create-QueryDefinition -QueryPayload $payload 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        #Query Payload
        [ValidateNotNullOrEmpty()]
        [string]$QueryPayload                               
  )
  If (-Not $global:defaultvRLICConnection)
    {
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    }
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/query-definitions"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $vrlic_body = $QueryPayload | ConvertFrom-Json 
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response     
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in creating vRLIC Query Definition"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-QueryDefinitions #########################

function Get-QueryDefinitions
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Query Definitions in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Query Definitions in a particular Org 
    .EXAMPLE
        Get-QueryDefinitions | where{$_.name -match "MM_PowervRLI"}
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$False)]
        # Size
        [ValidateNotNullOrEmpty()]
        [string]$PageSize=200,
      [Parameter (Mandatory=$False)]
        # QuerySource
        [ValidateNotNullOrEmpty()]
        [string]$QuerySource="USER_DEFINED"              
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/query-definitions"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "?size=$PageSize&source="+ $QuerySource
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Get -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content 
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRLIC Query Definitions"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}
######################### Remove-QueryDefinition #########################

function Remove-QueryDefinition
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Deletes vRLIC Query Definition in a particular Org 
    .DESCRIPTION
        This cmdlet deletes vRLIC Query Definition in a particular Org 
    .EXAMPLE
        Remove-QueryDefinition -QueryName "MMPowervRLICloudTest"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Name
        [ValidateNotNullOrEmpty()]
        [string]$QueryName            
  )
  If (-Not $global:defaultvRLICConnection) 
    { 
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    } 
  else
    {
      try {
            $query=Get-QueryDefinitions | where{$_.name -match "$QueryName"}
            $queryId=$query.id
            $vrlic_uri = "/vrlic/api/v1/query-definitions/"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ $queryId+ "?source=PowervRLICloud"
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vrlic_url -Method DELETE -Headers $vrlic_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            if ($response){
                Write-Host -ForegroundColor Green "Query Definition removed successfully" 
                break
            }      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in deleting vRLIC Query Definition "
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}
######################### Create-AlertDefinition #########################

function Create-AlertDefinition
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          09/11/2023
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Creates an Alert Definition in a particular Org 
    .DESCRIPTION
        This cmdlet creates an Alert Definition in a particular Org 
    .EXAMPLE
        $alertpayload = Get-Content ./alert.json | ConvertTo-Json
        Create-AlertDefinition  -AlertPayload $alertpayload
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        #Alert Payload
        [ValidateNotNullOrEmpty()]
        [string]$AlertPayload                               
  )
  If (-Not $global:defaultvRLICConnection)
    {
      Write-error "Not Connected to vRLI Cloud, please use Connect-vRLI-Cloud"
    }
  else
    {
      try {
            $vrlic_uri = "/vrlic/api/v1/alert"
            $url = $Connection.Server
            $vrlic_url = "https://"+ $url+ $vrlic_uri
            $cspauthtoken= $Connection.CSPToken         
            $vrlic_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $vrlic_body = $AlertPayload | ConvertFrom-Json             
            $response = Invoke-RestMethod -Uri $vrlic_url -Method Post -Headers $vrlic_headers -Body $vrlic_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response     
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRLI Cloud Session is no longer valid, please re-run the Connect-vRLI-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in creating vRLIC Alert Definition"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}
