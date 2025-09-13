#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Client Configuration Script for M365 Authentication Fix

.DESCRIPTION
    Configures client-side settings to resolve M365 authentication issues.
    Applies registry settings, trusted sites, and clears cached credentials.

.PARAMETER ApplyRegistryFix
    Applies necessary registry settings for Office and IE authentication

.PARAMETER ConfigureTrustedSites
    Adds M365 URLs to Internet Explorer trusted sites

.PARAMETER ClearCredentialCache
    Clears cached Office and Windows credentials

.PARAMETER RestartServices
    Restarts relevant services after configuration

.EXAMPLE
    .\configure-client.ps1 -ApplyRegistryFix -ConfigureTrustedSites -RestartServices

.NOTES
    Author: Your Name
    Version: 1.0
    Requires: PowerShell 5.1+, Administrative privileges
#>

param(
    [switch]$ApplyRegistryFix,
    [switch]$ConfigureTrustedSites,
    [switch]$ClearCredentialCache,
    [switch]$RestartServices,
    [switch]$WhatIf
)

function Write-ConfigMessage {
    param([string]$Message, [string]$Type = "Info")
    $timestamp = Get-Date -Format "HH:mm:ss"
    switch ($Type) {
        "Error" { Write-Host "[$timestamp] ERROR: $Message" -ForegroundColor Red }
        "Warning" { Write-Host "[$timestamp] WARNING: $Message" -ForegroundColor Yellow }
        "Success" { Write-Host "[$timestamp] SUCCESS: $Message" -ForegroundColor Green }
        default { Write-Host "[$timestamp] INFO: $Message" -ForegroundColor White }
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )
    
    try {
        if ($WhatIf) {
            Write-ConfigMessage "WHATIF: Would set registry $Path\$Name = $Value" "Info"
            return $true
        }
        
        # Create the registry path if it doesn't exist
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-ConfigMessage "Created registry path: $Path" "Info"
        }
        
        # Set the registry value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-ConfigMessage "Set registry value: $Path\$Name = $Value" "Success"
        return $true
    }
    catch {
        Write-ConfigMessage "Failed to set registry value $Path\$Name`: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Apply-OfficeRegistrySettings {
    Write-ConfigMessage "Applying Office authentication registry settings..."
    
    $settings = @(
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
            Name = "EnableADAL"
            Value = 1
            Description = "Enable Modern Authentication for Office 2016/2019/365"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Identity"
            Name = "Version"
            Value = 1
            Description = "Set Office Identity version"
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Office\15.0\Common\Identity"
            Name = "EnableADAL"
            Value = 1
            Description = "Enable Modern Authentication for Office 2013"
        }
    )
    
    $successCount = 0
    foreach ($setting in $settings) {
        Write-ConfigMessage "Setting: $($setting.Description)"
        if (Set-RegistryValue -Path $setting.Path -Name $setting.Name -Value $setting.Value) {
            $successCount++
        }
    }
    
    Write-ConfigMessage "Applied $successCount of $($settings.Count) Office registry settings" "Info"
}

function Apply-InternetExplorerSettings {
    Write-ConfigMessage "Applying Internet Explorer trusted sites settings..."
    
    $trustedSites = @(
        @{
            Domain = "microsoftonline.com"
            Subdomain = "login"
            Description = "Azure AD Login"
        },
        @{
            Domain = "windows.net"
            Subdomain = "login"
            Description = "Legacy Azure AD Login"
        },
        @{
            Domain = "live.com"
            Subdomain = "login"
            Description = "Microsoft Account Login"
        },
        @{
            Domain = "office365.com"
            Subdomain = "portal"
            Description = "Office 365 Portal"
        }
    )
    
    $successCount = 0
    foreach ($site in $trustedSites) {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($site.Domain)\$($site.Subdomain)"
        Write-ConfigMessage "Adding trusted site: https://$($site.Subdomain).$($site.Domain) - $($site.Description)"
        
        if (Set-RegistryValue -Path $regPath -Name "https" -Value 1) {
            $successCount++
        }
    }
    
    Write-ConfigMessage "Applied $successCount of $($trustedSites.Count) trusted site settings" "Info"
}

function Clear-OfficeCredentials {
    Write-ConfigMessage "Clearing Office credential cache..."
    
    try {
        if ($WhatIf) {
            Write-ConfigMessage "WHATIF: Would clear Office credential cache" "Info"
            return
        }
        
        # Clear Office credential cache
        $officeIdentityPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities"
        if (Test-Path $officeIdentityPath) {
            Remove-Item -Path $officeIdentityPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-ConfigMessage "Cleared Office 365 identity cache" "Success"
        }
        
        # Clear older Office versions
        $office2013Path = "HKCU:\Software\Microsoft\Office\15.0\Common\Identity\Identities"
        if (Test-Path $office2013Path) {
            Remove-Item -Path $office2013Path -Recurse -Force -ErrorAction SilentlyContinue
            Write-ConfigMessage "Cleared Office 2013 identity cache" "Success"
        }
        
        Write-ConfigMessage "Office credential cache cleared successfully" "Success"
    }
    catch {
        Write-ConfigMessage "Failed to clear Office credentials: $($_.Exception.Message)" "Error"
    }
}

function Clear-WindowsCredentials {
    Write-ConfigMessage "Clearing Windows credential cache..."
    
    try {
        if ($WhatIf) {
            Write-ConfigMessage "WHATIF: Would clear Windows credential cache" "Info"
            return
        }
        
        # Get all stored credentials related to Microsoft services
        $credentials = cmdkey /list | Where-Object { 
            $_ -like "*login.microsoftonline.com*" -or 
            $_ -like "*office365.com*" -or 
            $_ -like "*outlook.office365.com*" -or
            $_ -like "*login.windows.net*"
        }
        
        if ($credentials) {
            foreach ($cred in $credentials) {
                # Extract the target name
                if ($cred -match "Target: (.*)") {
                    $target = $matches[1]
                    cmdkey /delete:$target 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-ConfigMessage "Removed credential: $target" "Success"
                    }
                }
            }
        }
        else {
            Write-ConfigMessage "No Microsoft-related credentials found in cache" "Info"
        }
    }
    catch {
        Write-ConfigMessage "Failed to clear Windows credentials: $($_.Exception.Message)" "Error"
    }
}

function Restart-RelevantServices {
    Write-ConfigMessage "Restarting relevant services..."
    
    $services = @(
        "Themes",           # For registry changes to take effect
        "Browser",          # Internet Explorer settings
        "Winlogon"          # Authentication changes
    )
    
    foreach ($serviceName in $services) {
        try {
            if ($WhatIf) {
                Write-ConfigMessage "WHATIF: Would restart service $serviceName" "Info"
                continue
            }
            
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Restart-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                Write-ConfigMessage "Restarted service: $serviceName" "Success"
            }
            else {
                Write-ConfigMessage "Service $serviceName not running or not found" "Warning"
            }
        }
        catch {
            Write-ConfigMessage "Failed to restart service $serviceName`: $($_.Exception.Message)" "Warning"
        }
    }
}

function Test-Prerequisites {
    Write-ConfigMessage "Checking prerequisites..."
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-ConfigMessage "Script must be run as Administrator" "Error"
        return $false
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-ConfigMessage "PowerShell 5.1 or later required" "Error"
        return $false
    }
    
    return $true
}

# Main execution
function Main {
    Write-Host "Microsoft 365 Authentication Client Configuration" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    
    if ($WhatIf) {
        Write-Host "WHATIF MODE: No changes will be made" -ForegroundColor Yellow
    }
    
    if (-not (Test-Prerequisites)) {
        exit 1
    }
    
    $configCount = 0
    
    if ($ApplyRegistryFix) {
        Write-ConfigMessage "Applying registry fixes..." "Info"
        Apply-OfficeRegistrySettings
        $configCount++
    }
    
    if ($ConfigureTrustedSites) {
        Write-ConfigMessage "Configuring trusted sites..." "Info"
        Apply-InternetExplorerSettings
        $configCount++
    }
    
    if ($ClearCredentialCache) {
        Write-ConfigMessage "Clearing credential cache..." "Info"
        Clear-OfficeCredentials
        Clear-WindowsCredentials
        $configCount++
    }
    
    if ($RestartServices) {
        Write-ConfigMessage "Restarting services..." "Info"
        Restart-RelevantServices
        $configCount++
    }
    
    if ($configCount -eq 0) {
        Write-ConfigMessage "No configuration options selected. Use -ApplyRegistryFix, -ConfigureTrustedSites, -ClearCredentialCache, or -RestartServices" "Warning"
        return
    }
    
    Write-Host "`nConfiguration Summary:" -ForegroundColor Yellow
    Write-Host "=====================" -ForegroundColor Yellow
    Write-Host "Applied $configCount configuration sets" -ForegroundColor Green
    Write-Host "`nNext Steps:" -ForegroundColor Yellow
    Write-Host "1. Log off and log back on for registry changes to take effect" -ForegroundColor White
    Write-Host "2. Open Office applications to test authentication" -ForegroundColor White
    Write-Host "3. Run the validation script to verify configuration" -ForegroundColor White
    
    Write-ConfigMessage "Client configuration completed" "Success"
}

# Execute main function
Main