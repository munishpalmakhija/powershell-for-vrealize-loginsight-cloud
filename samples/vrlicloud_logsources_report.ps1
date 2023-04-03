#vrlicloud_logsources_report.ps1
#Author - Munishpal Makhija

#    ===========================================================================
#    Created by:    Munishpal Makhija
#    Release Date:  04/02/2023
#    Organization:  VMware
#    Version:       1.0
#    Blog:          https://www.munishpalmakhija.com/
#    Twitter:       @munishpal_singh
#    ===========================================================================

####################### Use Case #########################

######	Generate an HTML Report for Top 10 Log Sources in vRLI Cloud Environment / Org

######	It displays 2 tables 

###### By Source - It displays count of logs per log source IPs 
###### By Hostnames - It displays count of logs per hostname 

####################### Pre-requisites #########################

######	1 - PowervRLICloud Version 1.1 
######	2 - Connected to vRLI Cloud using Connect-vRLI-Cloud -APIToken $APIToken


####################### Usage #########################

######	Download the script and save it to a Folder and execute ./vrlicloud_logsources_report.ps1


####################### Dont Modify anything below this line #########################

$count=10

$Header = @"
<style>
body { background-color:#E5E4E2;
       font-family:sans-serif;
       font-size:10pt; }
td, th { border:0px solid black; 
         border-collapse:collapse;
         white-space:pre; }
th { color:white;
     background-color:black; }
table, tr, td, th { padding: 2px; margin: 0px ;white-space:pre; }
tr:nth-child(odd) {background-color: lightgray}
table { width:95%;margin-left:5px; margin-bottom:20px;}
h1 {
 font-family:sans-serif;
 color:#008000;
}
h2 {
 font-family:sans-serif;
 color:#0000A0;
}
h3 {
 font-family:sans-serif;
 color:#0000FF;
}
.alert {
 color: red; 
 }
.footer 
{ color:green; 
  margin-left:10px; 
  font-family:sans-serif;
  font-size:8pt;
  font-style:italic;
}
</style>
"@


$date = Get-Date
$user = whoami
$html = @()
$summary = @()

$html = "<h1> <center>vRLI Cloud Top $count Log Sources Report</center></h1>"

Write-Host -ForegroundColor Green "Fetching Log Source IPs"

$queryId = Post-Query-Request -SQlQuery “SELECT COUNT(*), source FROM logs GROUP BY source ORDER BY COUNT(*) DESC LIMIT $count” -Duration 1440
sleep 2
$response = Get-QueryResponse -QueryId $queryId
$results = $response.logQueryResults
$html+=$results | ConvertTo-Html -As Table -Fragment -PreContent  "<h2>By Source </h2>"

Write-Host -ForegroundColor Green "Fetching Log Source Hostnames"
$queryId = Post-Query-Request -SQlQuery “SELECT COUNT(*), source FROM logs GROUP BY hostname ORDER BY COUNT(*) DESC LIMIT $count” -Duration 1440
sleep 2
$response = Get-QueryResponse -QueryId $queryId
$results = $response.logQueryResults 
$html+=$results | ConvertTo-Html -As Table -Fragment -PreContent  "<h2>By Hostname </h2>"


$html += "<br><i> <center> Run by $user at $date  </center> </i>"
$html += "<br><i> <center> Generated using <a href=https://github.com/munishpalmakhija/powershell-for-vrealize-loginsight-cloud> Power vRLI Cloud </a></center> </i>"
$html += "<br><i> <center> Author - <a href=https://www.linkedin.com/in/munishpal-makhija-7139515> Munishpal Makhija </a></center> </i>"
$prefix = (Get-Date).ToString(‘M-d-y’)
$filename = "vRLI Cloud Top 10 Log Sources Report -"+ $prefix+ ".html"
ConvertTo-Html -Body "$html" -Title "vRLI Cloud Top 10 Log Sources Report" -Head $header| Out-File $filename

$directory = pwd
$file = "$directory/$filename"


####################### End of File #########################


