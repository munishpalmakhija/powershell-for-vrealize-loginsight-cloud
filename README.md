# Powershell for vRealize-LogInsight-Cloud


Powershell for vRealize-LogInsight-Cloud is a PowerShell module that abstracts the VMware vRealize LogInsight Cloud APIs to a set of easily used PowerShell functions. This tool provides a comprehensive command line environment for managing your VMware vRealize LogInsight Cloud. It is a.k.a PowervRLICloud

This module is not supported by VMware, and comes with no warranties expressed or implied. Please test and validate its functionality before using this product in a production environment.

# Pre-requisities 

You need to have following pre-requisties 

1.  vRealize LogInsight Cloud API Token 
2.  PowerShellVersion = '6.0' and Above

# Supported Environments

PowervRLICloud supports following environments

| Environment | Supported |
| --- | --- |
|vRLI-Cloud | :white_check_mark: |

# Install from PowerShell Gallery

You can install directly from Powershell Gallery by executing following command  

| Install-Module -Name PowervRLICloud  |
| ------------- |

# Manual Download

If you want to perform manual download in case you dont have access Powershell directly. It is a simple two-file module stored under module directory. 

1.  PowervRLICloud.psd1
2.  PowervRLICloud.psm1

To install it, download above 2 files to a PowerShell enabled machine and navigate to the folder and execute following command

| Import-Module .\PowervRLICloud.psd1  |
| ------------- |

# Getting Started

Quick Examples on how to get started 

| Example-1  |
| ------------- |
| Connect-vRLI-Cloud -APIToken "APIToken" |


| Example-2  |
| ------------- |
| Get-AlertDefinitions | where{$_.name -match "MMTest"} |


# Documentation

You can refer the <a href="https://munishpalmakhija.com/PowervRLICloudDocumentation.html">documentation</a> file which has instructions for every command

# Contribution

You can use following methods or you can reach out to me via <a href="https://twitter.com/munishpal_singh">twitter</a>

1. Bugs and Issues - Please use the issues register with details of the problem.
2. Feature Requests - Please use the issues register with details of what's required.
3. For Code contribution (bug fixes, or feature request), please request fork of the Project, create a feature branch, then submit a pull request.

# License 

Powershell for vRealize-LogInsight-Cloud is licensed under <a href="https://github.com/munishpalmakhija/powershell-for-vrealize-loginsight-cloud/blob/master/LICENSE.txt">GPL v2</a> .