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
    Version:       1.0
    Date:          10/12/2022
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
  $url = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize?source=PowervRLICloud"
  $headers = @{"Accept"="application/json";
 "Content-Type"="application/x-www-form-urlencoded";
}
$payload = @{"refresh_token"=$API;}
#$body= $payload | Convertto-Json
$response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $payload -ErrorAction:Stop
  if($response)
  {
    #$response = ($response | ConvertFrom-Json)
    if ($Region -eq "us")
    {
      $apiurl = "api.mgmt.cloud.vmware.com"
    }
    else
    {
        $apiurl = $Region + ".api.mgmt.cloud.vmware.com"
    }    
    # Setup a custom object to contain the parameters of the connection, including the URL to the CSP API & Access token
    $connection = [pscustomObject] @{
      "Server" = $apiurl      
      "CSPToken" = $response.access_token
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
        Remove-AlertDefinition -Name "Test"}
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
    Version:       1.0
    Date:          10/12/2022
    Organization:  VMware
    Blog:          https://munishpalmakhija.com
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRLIC Usage Report in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRLIC Usage Report in a particular Org 
    .EXAMPLE
        Get-UsageReport -UsageType "usageType=DATA_INGESTED_NON_BILLABLE_V2&usageType=DATA_INGESTED_BILLABLE_V2"   
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRLIC Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRLICConnection,
      [Parameter (Mandatory=$true)]
        # Usage Type
        [ValidateNotNullOrEmpty()]
        [string]$UsageType              
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
            $vrlic_url = "https://"+ $url+ $vrlic_uri+ "&"+ $usage_type+ "?source=PowervRLICloud"
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
                Write-Error "Error in retrieving vRLIC Usage Report"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

