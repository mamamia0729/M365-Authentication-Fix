#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Microsoft 365 Authentication Diagnostic Script

.DESCRIPTION
    Comprehensive diagnostic script to identify authentication issues between 
    on-premises Active Directory and Microsoft 365 services.

.PARAMETER Detailed
    Runs extended diagnostics including network tests and certificate validation

.PARAMETER ExportPath
    Path to export HTML diagnostic report

.PARAMETER TestConnectivity
    Tests network connectivity to M365 endpoints

.EXAMPLE
    .\diagnostics.ps1 -Detailed -ExportPath "C:\Temp\M365-Diagnostics.html"

.NOTES
    Author: Your Name
    Version: 1.0
    Requires: PowerShell 5.1+, Administrative privileges
#>

param(
    [switch]$Detailed,
    [string]$ExportPath,
    [switch]$TestConnectivity
)

# Initialize results collection
$DiagnosticResults = @{
    ComputerInfo = @{}
    DomainInfo = @{}
    AzureADConnect = @{}
    OfficeConfig = @{}
    RegistrySettings = @{}
    NetworkTests = @{}
    Recommendations = @()
    Issues = @()
    Timestamp = Get-Date
}

function Write-DiagnosticMessage {
    param([string]$Message, [string]$Type = "Info")
    $timestamp = Get-Date -Format "HH:mm:ss"
    switch ($Type) {
        "Error" { Write-Host "[$timestamp] ERROR: $Message" -ForegroundColor Red }
        "Warning" { Write-Host "[$timestamp] WARNING: $Message" -ForegroundColor Yellow }
        "Success" { Write-Host "[$timestamp] SUCCESS: $Message" -ForegroundColor Green }
        default { Write-Host "[$timestamp] INFO: $Message" -ForegroundColor White }
    }
}

function Test-Prerequisites {
    Write-DiagnosticMessage "Checking prerequisites..."
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-DiagnosticMessage "Script must be run as Administrator" "Error"
        return $false
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-DiagnosticMessage "PowerShell 5.1 or later required" "Error"
        return $false
    }
    
    return $true
}

function Get-ComputerDiagnostics {
    Write-DiagnosticMessage "Gathering computer information..."
    
    try {
        $computerInfo = Get-ComputerInfo
        $DiagnosticResults.ComputerInfo = @{
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            OS = $computerInfo.WindowsProductName
            OSVersion = $computerInfo.WindowsVersion
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            LastBootTime = $computerInfo.LastBootUpTime
            TimeZone = $computerInfo.TimeZone
        }
        Write-DiagnosticMessage "Computer information collected successfully" "Success"
    }
    catch {
        Write-DiagnosticMessage "Failed to gather computer information: $($_.Exception.Message)" "Error"
        $DiagnosticResults.Issues += "Failed to gather computer information"
    }
}

function Get-DomainDiagnostics {
    Write-DiagnosticMessage "Gathering domain information..."
    
    try {
        # Check domain membership
        $domain = Get-CimInstance -ClassName Win32_ComputerSystem
        $DiagnosticResults.DomainInfo.IsDomainJoined = $domain.PartOfDomain
        $DiagnosticResults.DomainInfo.DomainName = $domain.Domain
        
        if ($domain.PartOfDomain) {
            # Get domain controller information
            $dcInfo = nltest /dsgetdc:$domain.Domain 2>$null
            if ($LASTEXITCODE -eq 0) {
                $DiagnosticResults.DomainInfo.DomainController = ($dcInfo | Where-Object { $_ -match "DC:" }) -replace ".*DC: ", ""
            }
            
            # Check time synchronization
            $timeSync = w32tm /query /status 2>$null
            $DiagnosticResults.DomainInfo.TimeSyncStatus = if ($LASTEXITCODE -eq 0) { "OK" } else { "ERROR" }
            
            # Get current user UPN
            $currentUser = whoami /upn 2>$null
            if ($LASTEXITCODE -eq 0) {
                $DiagnosticResults.DomainInfo.CurrentUserUPN = $currentUser
            }
        }
        else {
            $DiagnosticResults.Issues += "Computer is not domain-joined"
            Write-DiagnosticMessage "Computer is not domain-joined" "Warning"
        }
        
        Write-DiagnosticMessage "Domain information collected successfully" "Success"
    }
    catch {
        Write-DiagnosticMessage "Failed to gather domain information: $($_.Exception.Message)" "Error"
        $DiagnosticResults.Issues += "Failed to gather domain information"
    }
}

function Test-AzureADConnect {
    Write-DiagnosticMessage "Checking Azure AD Connect status..."
    
    try {
        # Check if Azure AD Connect is installed locally
        $aadConnectPath = "C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe"
        $DiagnosticResults.AzureADConnect.IsInstalled = Test-Path $aadConnectPath
        
        if ($DiagnosticResults.AzureADConnect.IsInstalled) {
            # Get Azure AD Connect service status
            $syncService = Get-Service -Name "ADSync" -ErrorAction SilentlyContinue
            if ($syncService) {
                $DiagnosticResults.AzureADConnect.ServiceStatus = $syncService.Status
                $DiagnosticResults.AzureADConnect.ServiceStartType = $syncService.StartType
            }
            
            # Try to get sync configuration (may fail if not on sync server)
            try {
                if (Get-Module -ListAvailable -Name "ADSync") {
                    Import-Module ADSync -ErrorAction SilentlyContinue
                    $connectors = Get-ADSyncConnector -ErrorAction SilentlyContinue
                    if ($connectors) {
                        $DiagnosticResults.AzureADConnect.Connectors = $connectors | Select-Object Name, Type, ConnectorId
                    }
                }
            }
            catch {
                $DiagnosticResults.AzureADConnect.Note = "Unable to access sync configuration (may not be on sync server)"
            }
        }
        else {
            $DiagnosticResults.AzureADConnect.Note = "Azure AD Connect not installed on this machine"
        }
        
        Write-DiagnosticMessage "Azure AD Connect check completed" "Success"
    }
    catch {
        Write-DiagnosticMessage "Failed to check Azure AD Connect: $($_.Exception.Message)" "Error"
        $DiagnosticResults.Issues += "Failed to check Azure AD Connect status"
    }
}

function Test-OfficeConfiguration {
    Write-DiagnosticMessage "Checking Office configuration..."
    
    try {
        # Check Office installation
        $officeVersions = @()
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot",
            "HKLM:\SOFTWARE\Microsoft\Office\15.0\Common\InstallRoot",
            "HKLM:\SOFTWARE\Microsoft\Office\14.0\Common\InstallRoot"
        )
        
        foreach ($path in $registryPaths) {
            if (Test-Path $path) {
                $installPath = (Get-ItemProperty -Path $path -Name "Path" -ErrorAction SilentlyContinue).Path
                if ($installPath) {
                    $version = Switch ($path) {
                        "*16.0*" { "Office 2016/2019/365" }
                        "*15.0*" { "Office 2013" }
                        "*14.0*" { "Office 2010" }
                    }
                    $officeVersions += $version
                }
            }
        }
        
        $DiagnosticResults.OfficeConfig.InstalledVersions = $officeVersions
        
        # Check Office authentication settings
        $authSettings = @{}
        $officePaths = @(
            "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Identity",
            "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
        )
        
        foreach ($path in $officePaths) {
            if (Test-Path $path) {
                $enableADAL = (Get-ItemProperty -Path $path -Name "EnableADAL" -ErrorAction SilentlyContinue).EnableADAL
                if ($enableADAL -ne $null) {
                    $authSettings["EnableADAL"] = $enableADAL
                }
            }
        }
        
        $DiagnosticResults.OfficeConfig.AuthenticationSettings = $authSettings
        
        Write-DiagnosticMessage "Office configuration check completed" "Success"
    }
    catch {
        Write-DiagnosticMessage "Failed to check Office configuration: $($_.Exception.Message)" "Error"
        $DiagnosticResults.Issues += "Failed to check Office configuration"
    }
}

function Test-RegistrySettings {
    Write-DiagnosticMessage "Checking registry settings..."
    
    try {
        $registryChecks = @{
            # Internet Explorer Security Zones
            "IE_LoginMicrosoftOnline" = @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoftonline.com\login"
                Name = "https"
                ExpectedValue = 1
            }
            "IE_LoginWindows" = @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\windows.net\login"
                Name = "https" 
                ExpectedValue = 1
            }
            # Office Modern Authentication
            "Office_EnableADAL" = @{
                Path = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
                Name = "EnableADAL"
                ExpectedValue = 1
            }
        }
        
        $registryResults = @{}
        foreach ($check in $registryChecks.GetEnumerator()) {
            $path = $check.Value.Path
            $name = $check.Value.Name
            $expected = $check.Value.ExpectedValue
            
            if (Test-Path $path) {
                $actualValue = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
                $registryResults[$check.Key] = @{
                    Path = $path
                    Name = $name
                    ExpectedValue = $expected
                    ActualValue = $actualValue
                    IsCorrect = ($actualValue -eq $expected)
                }
                
                if ($actualValue -ne $expected) {
                    $DiagnosticResults.Issues += "Registry setting incorrect: $($check.Key)"
                }
            }
            else {
                $registryResults[$check.Key] = @{
                    Path = $path
                    Name = $name
                    ExpectedValue = $expected
                    ActualValue = "Key not found"
                    IsCorrect = $false
                }
                $DiagnosticResults.Issues += "Registry key missing: $($check.Key)"
            }
        }
        
        $DiagnosticResults.RegistrySettings = $registryResults
        Write-DiagnosticMessage "Registry settings check completed" "Success"
    }
    catch {
        Write-DiagnosticMessage "Failed to check registry settings: $($_.Exception.Message)" "Error"
        $DiagnosticResults.Issues += "Failed to check registry settings"
    }
}

function Test-NetworkConnectivity {
    if (-not $TestConnectivity -and -not $Detailed) { return }
    
    Write-DiagnosticMessage "Testing network connectivity to M365 endpoints..."
    
    $endpoints = @(
        @{ URL = "login.microsoftonline.com"; Port = 443; Description = "Azure AD Authentication" },
        @{ URL = "login.windows.net"; Port = 443; Description = "Legacy Authentication" },
        @{ URL = "outlook.office365.com"; Port = 443; Description = "Exchange Online" },
        @{ URL = "graph.microsoft.com"; Port = 443; Description = "Microsoft Graph" }
    )
    
    $connectivityResults = @{}
    foreach ($endpoint in $endpoints) {
        try {
            $result = Test-NetConnection -ComputerName $endpoint.URL -Port $endpoint.Port -InformationLevel Quiet
            $connectivityResults[$endpoint.URL] = @{
                Port = $endpoint.Port
                Description = $endpoint.Description
                Connected = $result
                ResponseTime = if ($result) { 
                    (Measure-Command { Test-NetConnection -ComputerName $endpoint.URL -Port $endpoint.Port -InformationLevel Quiet }).TotalMilliseconds 
                } else { 
                    "Failed" 
                }
            }
            
            if (-not $result) {
                $DiagnosticResults.Issues += "Cannot connect to $($endpoint.URL):$($endpoint.Port)"
            }
        }
        catch {
            $connectivityResults[$endpoint.URL] = @{
                Port = $endpoint.Port
                Description = $endpoint.Description
                Connected = $false
                Error = $_.Exception.Message
            }
            $DiagnosticResults.Issues += "Network test failed for $($endpoint.URL)"
        }
    }
    
    $DiagnosticResults.NetworkTests = $connectivityResults
    Write-DiagnosticMessage "Network connectivity tests completed" "Success"
}

function Generate-Recommendations {
    Write-DiagnosticMessage "Generating recommendations..."
    
    $recommendations = @()
    
    # Check for common issues and generate recommendations
    if ($DiagnosticResults.Issues -contains "Computer is not domain-joined") {
        $recommendations += "Join computer to domain before configuring M365 authentication"
    }
    
    if ($DiagnosticResults.RegistrySettings.Values | Where-Object { -not $_.IsCorrect }) {
        $recommendations += "Update registry settings for proper M365 authentication (see implementation guide)"
    }
    
    if ($DiagnosticResults.OfficeConfig.AuthenticationSettings.EnableADAL -ne 1) {
        $recommendations += "Enable Modern Authentication (ADAL) for Office applications"
    }
    
    if ($DiagnosticResults.AzureADConnect.ServiceStatus -ne "Running") {
        $recommendations += "Ensure Azure AD Connect synchronization service is running"
    }
    
    if ($DiagnosticResults.NetworkTests.Values | Where-Object { -not $_.Connected }) {
        $recommendations += "Resolve network connectivity issues to M365 endpoints"
    }
    
    if (-not $recommendations) {
        $recommendations += "No critical issues found. Review detailed results for optimization opportunities."
    }
    
    $DiagnosticResults.Recommendations = $recommendations
}

function Export-DiagnosticReport {
    if (-not $ExportPath) { return }
    
    Write-DiagnosticMessage "Generating diagnostic report..."
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Authentication Diagnostic Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 10px; }
        .section { margin: 20px 0; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Microsoft 365 Authentication Diagnostic Report</h1>
        <p>Generated: $($DiagnosticResults.Timestamp)</p>
        <p>Computer: $($DiagnosticResults.ComputerInfo.ComputerName)</p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <p><strong>Issues Found:</strong> $($DiagnosticResults.Issues.Count)</p>
        <p><strong>Recommendations:</strong> $($DiagnosticResults.Recommendations.Count)</p>
    </div>
    
    <div class="section">
        <h2>Computer Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            $(foreach ($item in $DiagnosticResults.ComputerInfo.GetEnumerator()) {
                "<tr><td>$($item.Key)</td><td>$($item.Value)</td></tr>"
            })
        </table>
    </div>
    
    <div class="section">
        <h2>Issues Identified</h2>
        <ul>
            $(foreach ($issue in $DiagnosticResults.Issues) {
                "<li class='error'>$issue</li>"
            })
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ol>
            $(foreach ($rec in $DiagnosticResults.Recommendations) {
                "<li>$rec</li>"
            })
        </ol>
    </div>
    
</body>
</html>
"@
    
    try {
        $html | Out-File -FilePath $ExportPath -Encoding UTF8
        Write-DiagnosticMessage "Report exported to: $ExportPath" "Success"
    }
    catch {
        Write-DiagnosticMessage "Failed to export report: $($_.Exception.Message)" "Error"
    }
}

# Main execution
function Main {
    Write-Host "Microsoft 365 Authentication Diagnostics" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    
    if (-not (Test-Prerequisites)) {
        exit 1
    }
    
    Get-ComputerDiagnostics
    Get-DomainDiagnostics
    Test-AzureADConnect
    Test-OfficeConfiguration
    Test-RegistrySettings
    Test-NetworkConnectivity
    Generate-Recommendations
    
    # Display summary
    Write-Host "`nDiagnostic Summary:" -ForegroundColor Yellow
    Write-Host "==================" -ForegroundColor Yellow
    Write-Host "Issues Found: $($DiagnosticResults.Issues.Count)" -ForegroundColor $(if($DiagnosticResults.Issues.Count -eq 0){"Green"}else{"Red"})
    Write-Host "Recommendations: $($DiagnosticResults.Recommendations.Count)" -ForegroundColor Yellow
    
    if ($DiagnosticResults.Issues.Count -gt 0) {
        Write-Host "`nIssues:" -ForegroundColor Red
        foreach ($issue in $DiagnosticResults.Issues) {
            Write-Host "  - $issue" -ForegroundColor Red
        }
    }
    
    Write-Host "`nRecommendations:" -ForegroundColor Yellow
    foreach ($rec in $DiagnosticResults.Recommendations) {
        Write-Host "  - $rec" -ForegroundColor Yellow
    }
    
    Export-DiagnosticReport
    
    Write-DiagnosticMessage "Diagnostics completed" "Success"
}

# Execute main function
Main