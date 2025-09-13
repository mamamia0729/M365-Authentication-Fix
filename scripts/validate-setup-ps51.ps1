#Requires -Version 5.1

<#
.SYNOPSIS
    Validation Script for M365 Authentication Configuration (PowerShell 5.1 Compatible)

.DESCRIPTION
    Tests and validates that M365 authentication is working correctly after
    applying the fix. Compatible with PowerShell 5.1.

.PARAMETER TestAllComponents
    Runs comprehensive tests on all authentication components

.PARAMETER GenerateReport
    Creates a text report of test results

.PARAMETER QuickTest
    Runs only essential authentication tests

.EXAMPLE
    .\validate-setup-ps51.ps1 -TestAllComponents -GenerateReport

.NOTES
    Author: Thinh Le
    Version: 1.0 (PowerShell 5.1 Compatible)
    Requires: PowerShell 5.1+
#>

param(
    [switch]$TestAllComponents,
    [switch]$GenerateReport,
    [switch]$QuickTest,
    [string]$ReportPath = "C:\Temp\M365-ValidationReport.txt"
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
        "Error" { Write-Host "[$timestamp] ERROR: $Message" -ForegroundColor Red }
        "Warning" { Write-Host "[$timestamp] WARNING: $Message" -ForegroundColor Yellow }
        "Success" { Write-Host "[$timestamp] SUCCESS: $Message" -ForegroundColor Green }
        "Test" { Write-Host "[$timestamp] TEST: $Message" -ForegroundColor Cyan }
        default { Write-Host "[$timestamp] INFO: $Message" -ForegroundColor White }
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
                    Write-ValidationMessage "PASS: $($testInfo.Description)" "Success"
                    $testsPassed++
                    $TestResults.TestSummary.Passed++
                    $status = "PASS"
                }
                else {
                    if ($testInfo.Optional) {
                        Write-ValidationMessage "OPTIONAL: $($testInfo.Description) - Expected $($testInfo.ExpectedValue), Got $actualValue" "Warning"
                        $TestResults.TestSummary.Warnings++
                        $status = "WARNING"
                    }
                    else {
                        Write-ValidationMessage "FAIL: $($testInfo.Description) - Expected $($testInfo.ExpectedValue), Got $actualValue" "Error"
                        $TestResults.TestSummary.Failed++
                        $status = "FAIL"
                    }
                }
            }
            else {
                if ($testInfo.Optional) {
                    Write-ValidationMessage "OPTIONAL: $($testInfo.Description) - Registry path not found" "Warning"
                    $TestResults.TestSummary.Warnings++
                    $status = "WARNING"
                }
                else {
                    Write-ValidationMessage "FAIL: $($testInfo.Description) - Registry path not found" "Error"
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
            Write-ValidationMessage "ERROR: $($testInfo.Description) - $($_.Exception.Message)" "Error"
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
                Write-ValidationMessage "PASS: $($endpoint.Description) - Connected" "Success"
                $TestResults.TestSummary.Passed++
                $status = "PASS"
            }
            else {
                if ($endpoint.Critical) {
                    Write-ValidationMessage "FAIL: $($endpoint.Description) - Connection failed" "Error"
                    $TestResults.TestSummary.Failed++
                    $status = "FAIL"
                }
                else {
                    Write-ValidationMessage "WARNING: $($endpoint.Description) - Connection failed (non-critical)" "Warning"
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
            Write-ValidationMessage "ERROR: $($endpoint.Description) - $($_.Exception.Message)" "Error"
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
        Write-ValidationMessage "PASS: Office installations found - $($officeVersions -join ', ')" "Success"
        $TestResults.OfficeTests.InstallationStatus = "Installed"
        $TestResults.OfficeTests.Versions = $officeVersions
    }
    else {
        Write-ValidationMessage "WARNING: No Office installations detected" "Warning"
        $TestResults.OfficeTests.InstallationStatus = "Not Found"
        return
    }
    
    # Test Office authentication configuration
    $TestResults.TestSummary.Total++
    
    $office365Path = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
    if (Test-Path $office365Path) {
        $enableADAL = (Get-ItemProperty -Path $office365Path -Name "EnableADAL" -ErrorAction SilentlyContinue).EnableADAL
        
        if ($enableADAL -eq 1) {
            Write-ValidationMessage "PASS: Office Modern Authentication - Enabled" "Success"
            $TestResults.TestSummary.Passed++
            $TestResults.OfficeTests.ModernAuthStatus = "Enabled"
        }
        else {
            Write-ValidationMessage "FAIL: Office Modern Authentication - Disabled or not configured" "Error"
            $TestResults.TestSummary.Failed++
            $TestResults.OfficeTests.ModernAuthStatus = "Disabled"
        }
    }
    else {
        Write-ValidationMessage "FAIL: Office authentication registry not found" "Error"
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
            Write-ValidationMessage "PASS: Computer is domain-joined - $($domain.Domain)" "Success"
            $TestResults.TestSummary.Passed++
            $TestResults.AuthenticationTests.DomainStatus = "Joined"
            $TestResults.AuthenticationTests.DomainName = $domain.Domain
            
            # Test domain controller connectivity
            $TestResults.TestSummary.Total++
            $dcTest = nltest /dsgetdc:$domain.Domain 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-ValidationMessage "PASS: Domain controller connectivity - OK" "Success"
                $TestResults.TestSummary.Passed++
                $TestResults.AuthenticationTests.DCConnectivity = "OK"
            }
            else {
                Write-ValidationMessage "FAIL: Domain controller connectivity - Failed" "Error"
                $TestResults.TestSummary.Failed++
                $TestResults.AuthenticationTests.DCConnectivity = "Failed"
            }
            
            # Check current user UPN
            $TestResults.TestSummary.Total++
            $upn = whoami /upn 2>$null
            if ($LASTEXITCODE -eq 0 -and $upn) {
                Write-ValidationMessage "PASS: User UPN - $upn" "Success"
                $TestResults.TestSummary.Passed++
                $TestResults.AuthenticationTests.UserUPN = $upn
            }
            else {
                Write-ValidationMessage "WARNING: User UPN - Not available or not configured" "Warning"
                $TestResults.TestSummary.Warnings++
                $TestResults.AuthenticationTests.UserUPN = "Not Available"
            }
        }
        else {
            Write-ValidationMessage "FAIL: Computer is not domain-joined" "Error"
            $TestResults.TestSummary.Failed++
            $TestResults.AuthenticationTests.DomainStatus = "Not Joined"
        }
    }
    catch {
        Write-ValidationMessage "ERROR: Domain authentication test failed - $($_.Exception.Message)" "Error"
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
    
    try {
        $reportContent = @()
        $reportContent += "======================================================"
        $reportContent += "Microsoft 365 Authentication Validation Report"
        $reportContent += "======================================================"
        $reportContent += "Generated: $($TestResults.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))"
        $reportContent += "Computer: $($env:COMPUTERNAME)"
        $reportContent += ""
        $reportContent += "OVERALL STATUS: $($TestResults.OverallStatus)"
        $reportContent += ""
        $reportContent += "TEST SUMMARY:"
        $reportContent += "Total Tests: $($TestResults.TestSummary.Total)"
        $reportContent += "Passed: $($TestResults.TestSummary.Passed)"
        $reportContent += "Failed: $($TestResults.TestSummary.Failed)"
        $reportContent += "Warnings: $($TestResults.TestSummary.Warnings)"
        $reportContent += ""
        $reportContent += "REGISTRY TESTS:"
        foreach ($test in $TestResults.RegistryTests.GetEnumerator()) {
            $reportContent += "$($test.Value.Description): $($test.Value.Status)"
        }
        $reportContent += ""
        $reportContent += "RECOMMENDATIONS:"
        foreach ($rec in $TestResults.Recommendations) {
            $reportContent += "- $rec"
        }
        $reportContent += ""
        $reportContent += "======================================================"
        
        $reportContent | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-ValidationMessage "Validation report generated: $ReportPath" "Success"
    }
    catch {
        Write-ValidationMessage "Failed to generate report: $($_.Exception.Message)" "Error"
    }
}

# Main execution
function Main {
    Write-Host "Microsoft 365 Authentication Validation (PowerShell 5.1)" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
    
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
    Write-Host ""
    Write-Host "Validation Summary:" -ForegroundColor Yellow
    Write-Host "==================" -ForegroundColor Yellow
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
        Write-Host ""
        Write-Host "Recommendations:" -ForegroundColor Yellow
        foreach ($rec in $TestResults.Recommendations) {
            Write-Host "  - $rec" -ForegroundColor Yellow
        }
    }
    
    Export-ValidationReport
    
    Write-ValidationMessage "Validation completed" "Success"
}

# Execute main function
Main