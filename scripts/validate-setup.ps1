#Requires -Version 5.1

<#
.SYNOPSIS
    Validation Script for M365 Authentication Configuration

.DESCRIPTION
    Tests and validates that M365 authentication is working correctly after
    applying the fix. Checks SSO functionality and generates a test report.

.PARAMETER TestAllComponents
    Runs comprehensive tests on all authentication components

.PARAMETER GenerateReport
    Creates an HTML report of test results

.PARAMETER QuickTest
    Runs only essential authentication tests

.EXAMPLE
    .\validate-setup.ps1 -TestAllComponents -GenerateReport

.NOTES
    Author: Your Name
    Version: 1.0
    Requires: PowerShell 5.1+
#>

param(
    [switch]$TestAllComponents,
    [switch]$GenerateReport,
    [switch]$QuickTest,
    [string]$ReportPath = "C:\Temp\M365-ValidationReport.html"
)

# Initialize test results
$TestResults = @{
    ComputerInfo = @{}
    RegistryTests = @{}
    NetworkTests = @{}
    OfficeTests = @{}
    AuthenticationTests = @{}
    OverallStatus = "Unknown"
    TestSummary = @{
        Total = 0
        Passed = 0
        Failed = 0
        Warnings = 0
    }
    Timestamp = Get-Date
    Recommendations = @()
}

function Write-ValidationMessage {
    param([string]$Message, [string]$Type = "Info")
    $timestamp = Get-Date -Format "HH:mm:ss"
    switch ($Type) {
        "Error" { Write-Host "[$timestamp] ❌ ERROR: $Message" -ForegroundColor Red }
        "Warning" { Write-Host "[$timestamp] ⚠️  WARNING: $Message" -ForegroundColor Yellow }
        "Success" { Write-Host "[$timestamp] ✅ SUCCESS: $Message" -ForegroundColor Green }
        "Test" { Write-Host "[$timestamp] 🧪 TEST: $Message" -ForegroundColor Cyan }
        default { Write-Host "[$timestamp] ℹ️  INFO: $Message" -ForegroundColor White }
    }
}

function Test-RegistryConfiguration {
    Write-ValidationMessage "Testing registry configuration..." "Test"
    
    $registryTests = @{
        "Office_EnableADAL_Machine" = @{
            Path = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
            Name = "EnableADAL"
            ExpectedValue = 1
            Description = "Office Modern Authentication (Machine)"
        }
        "Office_EnableADAL_User" = @{
            Path = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
            Name = "EnableADAL"
            ExpectedValue = 1
            Description = "Office Modern Authentication (User)"
            Optional = $true
        }
        "IE_TrustedSite_Login" = @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoftonline.com\login"
            Name = "https"
            ExpectedValue = 1
            Description = "IE Trusted Site - Azure AD Login"
        }
    }
    
    $testsPassed = 0
    $testsTotal = 0
    
    foreach ($test in $registryTests.GetEnumerator()) {
        $testsTotal++
        $TestResults.TestSummary.Total++
        
        $testInfo = $test.Value
        $testName = $test.Key
        
        Write-ValidationMessage "Checking: $($testInfo.Description)" "Test"
        
        try {
            if (Test-Path $testInfo.Path) {
                $actualValue = (Get-ItemProperty -Path $testInfo.Path -Name $testInfo.Name -ErrorAction SilentlyContinue).$($testInfo.Name)
                
                if ($actualValue -eq $testInfo.ExpectedValue) {
                    Write-ValidationMessage "✅ $($testInfo.Description): PASS" "Success"
                    $testsPassed++
                    $TestResults.TestSummary.Passed++
                    $status = "PASS"
                }
                else {
                    if ($testInfo.Optional) {
                        Write-ValidationMessage "⚠️  $($testInfo.Description): OPTIONAL - Expected $($testInfo.ExpectedValue), Got $actualValue" "Warning"
                        $TestResults.TestSummary.Warnings++
                        $status = "WARNING"
                    }
                    else {
                        Write-ValidationMessage "❌ $($testInfo.Description): FAIL - Expected $($testInfo.ExpectedValue), Got $actualValue" "Error"
                        $TestResults.TestSummary.Failed++
                        $status = "FAIL"
                    }
                }
            }
            else {
                if ($testInfo.Optional) {
                    Write-ValidationMessage "⚠️  $($testInfo.Description): OPTIONAL - Registry path not found" "Warning"
                    $TestResults.TestSummary.Warnings++
                    $status = "WARNING"
                }
                else {
                    Write-ValidationMessage "❌ $($testInfo.Description): FAIL - Registry path not found" "Error"
                    $TestResults.TestSummary.Failed++
                    $status = "FAIL"
                }
            }
            
            $TestResults.RegistryTests[$testName] = @{
                Description = $testInfo.Description
                Path = $testInfo.Path
                Name = $testInfo.Name
                ExpectedValue = $testInfo.ExpectedValue
                ActualValue = $actualValue
                Status = $status
                Optional = $testInfo.Optional -eq $true
            }
        }
        catch {
            Write-ValidationMessage "❌ $($testInfo.Description): ERROR - $($_.Exception.Message)" "Error"
            $TestResults.TestSummary.Failed++
            $TestResults.RegistryTests[$testName] = @{
                Description = $testInfo.Description
                Status = "ERROR"
                Error = $_.Exception.Message
            }
        }
    }
    
    Write-ValidationMessage "Registry tests completed: $testsPassed/$testsTotal passed" "Info"
}

function Test-NetworkConnectivity {
    if ($QuickTest) { return }
    
    Write-ValidationMessage "Testing network connectivity..." "Test"
    
    $endpoints = @(
        @{ URL = "login.microsoftonline.com"; Port = 443; Description = "Azure AD Authentication"; Critical = $true },
        @{ URL = "outlook.office365.com"; Port = 443; Description = "Exchange Online"; Critical = $true },
        @{ URL = "graph.microsoft.com"; Port = 443; Description = "Microsoft Graph"; Critical = $false }
    )
    
    foreach ($endpoint in $endpoints) {
        $TestResults.TestSummary.Total++
        
        try {
            Write-ValidationMessage "Testing connection to $($endpoint.URL):$($endpoint.Port)..." "Test"
            
            $result = Test-NetConnection -ComputerName $endpoint.URL -Port $endpoint.Port -InformationLevel Quiet -WarningAction SilentlyContinue
            
            if ($result) {
                Write-ValidationMessage "✅ $($endpoint.Description): Connected" "Success"
                $TestResults.TestSummary.Passed++
                $status = "PASS"
            }
            else {
                if ($endpoint.Critical) {
                    Write-ValidationMessage "❌ $($endpoint.Description): Connection failed" "Error"
                    $TestResults.TestSummary.Failed++
                    $status = "FAIL"
                }
                else {
                    Write-ValidationMessage "⚠️  $($endpoint.Description): Connection failed (non-critical)" "Warning"
                    $TestResults.TestSummary.Warnings++
                    $status = "WARNING"
                }
            }
            
            $TestResults.NetworkTests[$endpoint.URL] = @{
                Description = $endpoint.Description
                Port = $endpoint.Port
                Connected = $result
                Status = $status
                Critical = $endpoint.Critical
            }
        }
        catch {
            Write-ValidationMessage "❌ $($endpoint.Description): ERROR - $($_.Exception.Message)" "Error"
            $TestResults.TestSummary.Failed++
            $TestResults.NetworkTests[$endpoint.URL] = @{
                Description = $endpoint.Description
                Status = "ERROR"
                Error = $_.Exception.Message
            }
        }
    }
}

function Test-OfficeConfiguration {
    Write-ValidationMessage "Testing Office configuration..." "Test"
    
    # Check if Office is installed
    $officeVersions = @()
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot",
        "HKLM:\SOFTWARE\Microsoft\Office\15.0\Common\InstallRoot"
    )
    
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $installPath = (Get-ItemProperty -Path $path -Name "Path" -ErrorAction SilentlyContinue).Path
            if ($installPath) {
                $version = if ($path -like "*16.0*") { "Office 2016/2019/365" } else { "Office 2013" }
                $officeVersions += $version
            }
        }
    }
    
    if ($officeVersions.Count -gt 0) {
        Write-ValidationMessage "✅ Office installations found: $($officeVersions -join ', ')" "Success"
        $TestResults.OfficeTests.InstallationStatus = "Installed"
        $TestResults.OfficeTests.Versions = $officeVersions
    }
    else {
        Write-ValidationMessage "⚠️  No Office installations detected" "Warning"
        $TestResults.OfficeTests.InstallationStatus = "Not Found"
        return
    }
    
    # Test Office authentication configuration
    $TestResults.TestSummary.Total++
    
    $office365Path = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
    if (Test-Path $office365Path) {
        $enableADAL = (Get-ItemProperty -Path $office365Path -Name "EnableADAL" -ErrorAction SilentlyContinue).EnableADAL
        
        if ($enableADAL -eq 1) {
            Write-ValidationMessage "✅ Office Modern Authentication: Enabled" "Success"
            $TestResults.TestSummary.Passed++
            $TestResults.OfficeTests.ModernAuthStatus = "Enabled"
        }
        else {
            Write-ValidationMessage "❌ Office Modern Authentication: Disabled or not configured" "Error"
            $TestResults.TestSummary.Failed++
            $TestResults.OfficeTests.ModernAuthStatus = "Disabled"
        }
    }
    else {
        Write-ValidationMessage "❌ Office authentication registry not found" "Error"
        $TestResults.TestSummary.Failed++
        $TestResults.OfficeTests.ModernAuthStatus = "Not Configured"
    }
}

function Test-DomainAuthentication {
    Write-ValidationMessage "Testing domain authentication..." "Test"
    
    try {
        $TestResults.TestSummary.Total++
        
        # Check if computer is domain-joined
        $domain = Get-CimInstance -ClassName Win32_ComputerSystem
        
        if ($domain.PartOfDomain) {
            Write-ValidationMessage "✅ Computer is domain-joined: $($domain.Domain)" "Success"
            $TestResults.TestSummary.Passed++
            $TestResults.AuthenticationTests.DomainStatus = "Joined"
            $TestResults.AuthenticationTests.DomainName = $domain.Domain
            
            # Test domain controller connectivity
            $TestResults.TestSummary.Total++
            $dcTest = nltest /dsgetdc:$domain.Domain 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-ValidationMessage "✅ Domain controller connectivity: OK" "Success"
                $TestResults.TestSummary.Passed++
                $TestResults.AuthenticationTests.DCConnectivity = "OK"
            }
            else {
                Write-ValidationMessage "❌ Domain controller connectivity: Failed" "Error"
                $TestResults.TestSummary.Failed++
                $TestResults.AuthenticationTests.DCConnectivity = "Failed"
            }
            
            # Check current user UPN
            $TestResults.TestSummary.Total++
            $upn = whoami /upn 2>$null
            if ($LASTEXITCODE -eq 0 -and $upn) {
                Write-ValidationMessage "✅ User UPN: $upn" "Success"
                $TestResults.TestSummary.Passed++
                $TestResults.AuthenticationTests.UserUPN = $upn
            }
            else {
                Write-ValidationMessage "⚠️  User UPN: Not available or not configured" "Warning"
                $TestResults.TestSummary.Warnings++
                $TestResults.AuthenticationTests.UserUPN = "Not Available"
            }
        }
        else {
            Write-ValidationMessage "❌ Computer is not domain-joined" "Error"
            $TestResults.TestSummary.Failed++
            $TestResults.AuthenticationTests.DomainStatus = "Not Joined"
        }
    }
    catch {
        Write-ValidationMessage "❌ Domain authentication test failed: $($_.Exception.Message)" "Error"
        $TestResults.TestSummary.Failed++
        $TestResults.AuthenticationTests.DomainStatus = "Error"
        $TestResults.AuthenticationTests.Error = $_.Exception.Message
    }
}

function Generate-Recommendations {
    Write-ValidationMessage "Generating recommendations..." "Info"
    
    $recommendations = @()
    
    # Check for failed registry tests
    $failedRegistryTests = $TestResults.RegistryTests.Values | Where-Object { $_.Status -eq "FAIL" }
    if ($failedRegistryTests) {
        $recommendations += "Run the client configuration script with -ApplyRegistryFix to fix registry settings"
    }
    
    # Check for failed network tests
    $failedNetworkTests = $TestResults.NetworkTests.Values | Where-Object { $_.Status -eq "FAIL" -and $_.Critical }
    if ($failedNetworkTests) {
        $recommendations += "Check firewall and network configuration for M365 endpoints"
    }
    
    # Check Office configuration
    if ($TestResults.OfficeTests.ModernAuthStatus -eq "Disabled") {
        $recommendations += "Enable Modern Authentication for Office applications"
    }
    
    # Check domain authentication
    if ($TestResults.AuthenticationTests.DomainStatus -eq "Not Joined") {
        $recommendations += "Join computer to domain before configuring M365 SSO"
    }
    
    # Overall recommendations based on test results
    if ($TestResults.TestSummary.Failed -eq 0 -and $TestResults.TestSummary.Warnings -le 2) {
        $recommendations += "Configuration appears to be working correctly. Test with actual Office applications."
    }
    
    if (-not $recommendations) {
        $recommendations += "Review detailed test results for optimization opportunities."
    }
    
    $TestResults.Recommendations = $recommendations
}

function Set-OverallStatus {
    if ($TestResults.TestSummary.Failed -eq 0) {
        if ($TestResults.TestSummary.Warnings -eq 0) {
            $TestResults.OverallStatus = "EXCELLENT"
        }
        elseif ($TestResults.TestSummary.Warnings -le 2) {
            $TestResults.OverallStatus = "GOOD"
        }
        else {
            $TestResults.OverallStatus = "NEEDS_ATTENTION"
        }
    }
    else {
        $TestResults.OverallStatus = "NEEDS_FIXES"
    }
}

function Export-ValidationReport {
    if (-not $GenerateReport) { return }
    
    Write-ValidationMessage "Generating validation report..." "Info"
    
    $statusColor = switch ($TestResults.OverallStatus) {
        "EXCELLENT" { "green" }
        "GOOD" { "lightgreen" }
        "NEEDS_ATTENTION" { "orange" }
        "NEEDS_FIXES" { "red" }
        default { "gray" }
    }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Authentication Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 15px; border-radius: 5px; }
        .status-card { background-color: $statusColor; color: white; padding: 10px; border-radius: 5px; margin: 10px 0; text-align: center; }
        .section { background-color: white; margin: 20px 0; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .metric { display: inline-block; margin: 0 15px; }
        .metric-value { font-size: 24px; font-weight: bold; }
        .metric-label { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Microsoft 365 Authentication Validation Report</h1>
        <p>Generated: $($TestResults.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p>Computer: $($env:COMPUTERNAME)</p>
    </div>
    
    <div class="status-card">
        <h2>Overall Status: $($TestResults.OverallStatus)</h2>
    </div>
    
    <div class="section">
        <h2>📊 Test Summary</h2>
        <div style="text-align: center;">
            <div class="metric">
                <div class="metric-value" style="color: #0078d4;">$($TestResults.TestSummary.Total)</div>
                <div class="metric-label">Total Tests</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: green;">$($TestResults.TestSummary.Passed)</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: red;">$($TestResults.TestSummary.Failed)</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: orange;">$($TestResults.TestSummary.Warnings)</div>
                <div class="metric-label">Warnings</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>🔧 Registry Configuration Tests</h2>
        <table>
            <tr><th>Test</th><th>Status</th><th>Expected</th><th>Actual</th></tr>
            $(foreach ($test in $TestResults.RegistryTests.GetEnumerator()) {
                $statusClass = switch($test.Value.Status) {
                    "PASS" { "pass" }
                    "FAIL" { "fail" }
                    default { "warning" }
                }
                "<tr><td>$($test.Value.Description)</td><td class='$statusClass'>$($test.Value.Status)</td><td>$($test.Value.ExpectedValue)</td><td>$($test.Value.ActualValue)</td></tr>"
            })
        </table>
    </div>
    
    <div class="section">
        <h2>🎯 Recommendations</h2>
        <ol>
            $(foreach ($rec in $TestResults.Recommendations) {
                "<li>$rec</li>"
            })
        </ol>
    </div>
    
    <div class="section">
        <h2>📝 Next Steps</h2>
        <ul>
            <li>Address any failed tests using the implementation guide</li>
            <li>Test actual Office applications (Outlook, Word, Excel)</li>
            <li>Monitor authentication behavior for 24-48 hours</li>
            <li>Collect user feedback on authentication experience</li>
        </ul>
    </div>
    
</body>
</html>
"@
    
    try {
        $html | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-ValidationMessage "Validation report generated: $ReportPath" "Success"
    }
    catch {
        Write-ValidationMessage "Failed to generate report: $($_.Exception.Message)" "Error"
    }
}

# Main execution
function Main {
    Write-Host "🔐 Microsoft 365 Authentication Validation" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    
    # Gather computer info
    $TestResults.ComputerInfo = @{
        ComputerName = $env:COMPUTERNAME
        Domain = $env:USERDOMAIN
        User = $env:USERNAME
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    
    # Run tests based on parameters
    Test-RegistryConfiguration
    
    if ($TestAllComponents -or -not $QuickTest) {
        Test-NetworkConnectivity
    }
    
    Test-OfficeConfiguration
    Test-DomainAuthentication
    
    Generate-Recommendations
    Set-OverallStatus
    
    # Display summary
    Write-Host "`n📊 Validation Summary:" -ForegroundColor Yellow
    Write-Host "=====================" -ForegroundColor Yellow
    Write-Host "Overall Status: $($TestResults.OverallStatus)" -ForegroundColor $(
        switch($TestResults.OverallStatus) {
            "EXCELLENT" { "Green" }
            "GOOD" { "Green" }
            "NEEDS_ATTENTION" { "Yellow" }
            "NEEDS_FIXES" { "Red" }
            default { "White" }
        }
    )
    Write-Host "Tests Passed: $($TestResults.TestSummary.Passed)/$($TestResults.TestSummary.Total)" -ForegroundColor Green
    Write-Host "Tests Failed: $($TestResults.TestSummary.Failed)" -ForegroundColor $(if($TestResults.TestSummary.Failed -eq 0){"Green"}else{"Red"})
    Write-Host "Warnings: $($TestResults.TestSummary.Warnings)" -ForegroundColor $(if($TestResults.TestSummary.Warnings -eq 0){"Green"}else{"Yellow"})
    
    if ($TestResults.Recommendations.Count -gt 0) {
        Write-Host "`n🎯 Recommendations:" -ForegroundColor Yellow
        foreach ($rec in $TestResults.Recommendations) {
            Write-Host "  • $rec" -ForegroundColor Yellow
        }
    }
    
    Export-ValidationReport
    
    Write-ValidationMessage "Validation completed" "Success"
}

# Execute main function
Main