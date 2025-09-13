# Implementation Guide: Microsoft 365 Authentication Fix

## Overview

This guide provides step-by-step instructions to resolve dual login requirements and implement seamless SSO for Microsoft 365 in enterprise environments.

## Prerequisites Checklist

Before starting, ensure you have:

- [ ] Domain Administrator rights in on-premises Active Directory
- [ ] Global Administrator rights in Microsoft 365/Azure AD
- [ ] Local Administrator rights on target client machines
- [ ] Access to Azure AD Connect server
- [ ] PowerShell 5.1 or later on administrative workstation
- [ ] Network connectivity to all required endpoints (see [Network Requirements](#network-requirements))

## Phase 1: Assessment and Preparation

### Step 1: Run Initial Diagnostics

```powershell
# Run the diagnostic script to assess current state
.\scripts\diagnostics.ps1 -Detailed -ExportPath "C:\Temp\M365-Diagnostics.html"
```

### Step 2: Backup Current Configuration

```powershell
# Backup Azure AD Connect configuration
Export-ADSyncConfiguration -Path "C:\Backup\AADConnect_$(Get-Date -Format 'yyyyMMdd')"

# Backup relevant Group Policy settings
Get-GPO -All | Backup-GPO -Path "C:\Backup\GPO_$(Get-Date -Format 'yyyyMMdd')"
```

### Step 3: Document Current State

Create a baseline document including:
- Current authentication methods in use
- Identified UPN mismatches
- Existing Group Policy configurations
- User-reported authentication issues

## Phase 2: Azure AD Connect Configuration

### Step 4: Fix UPN Matching Issues

```powershell
# Check for UPN mismatches
$OnPremUsers = Get-ADUser -Filter * -Properties UserPrincipalName | Select-Object SamAccountName, UserPrincipalName
$AzureADUsers = Get-AzureADUser -All $true | Select-Object UserPrincipalName, OnPremisesSecurityIdentifier

# Compare and identify mismatches (detailed script in scripts/fix-upn-mismatch.ps1)
```

**Manual Steps:**
1. Open Azure AD Connect on the sync server
2. Navigate to **Additional tasks** → **Customize synchronization options**
3. Verify **User Principal Name** attribute mapping
4. Ensure on-premises UPN suffix matches Azure AD domain

### Step 5: Enable Password Hash Synchronization

1. **On Azure AD Connect Server:**
   ```powershell
   # Check current sync method
   Get-ADSyncConnector | Select-Object Name, Type, ConnectorId
   
   # Enable Password Hash Sync if not already enabled
   Set-ADSyncPasswordSync -SourceConnector "domain.local" -Enable $true
   ```

2. **Through Azure AD Connect Wizard:**
   - Run Azure AD Connect wizard
   - Select **Change user sign-in**
   - Choose **Password Hash Synchronization**
   - Complete the wizard

### Step 6: Configure Azure AD Seamless SSO

```powershell
# Enable Seamless SSO
Set-ADSyncAADPasswordSyncConfiguration -SourceConnector "domain.local" -TargetConnector "tenant.onmicrosoft.com - AAD" -Enable $true

# Configure Kerberos decryption key
Enable-ADSyncAADSeamlessSSO -Enable $true
```

**Additional Steps:**
1. Configure SPN for seamless SSO account
2. Distribute computer account password to all domain controllers
3. Add Azure AD URLs to Intranet zone via Group Policy

## Phase 3: Group Policy Configuration

### Step 7: Deploy Office Authentication Policies

Create and configure the following GPO settings:

**Computer Configuration → Administrative Templates → Microsoft Office 2016/2019/365 → Security Settings:**

```
Policy: "Enable Automatic Sign-in"
Setting: Enabled
Value: 1

Policy: "Automatically sign into Office with Windows credentials"
Setting: Enabled

Policy: "Block signing into Office"
Setting: Disabled
```

### Step 8: Configure Browser Authentication

**Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options:**

```
Policy: "Network security: Allow Local System to use computer identity for NTLM"
Setting: Enabled
```

**User Configuration → Administrative Templates → Windows Components → Internet Explorer → Internet Control Panel → Security Page:**

```
Policy: "Site to Zone Assignment List"
Setting: Enabled
Value Names and Values:
- https://login.microsoftonline.com = 1
- https://login.windows.net = 1  
- https://login.live.com = 1
- https://account.activedirectory.windowsazure.com = 1
```

### Step 9: Registry Configuration via GPO

Deploy these registry settings through Group Policy:

**Computer Configuration → Preferences → Windows Settings → Registry:**

```
Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\microsoftonline.com\login
Name: https
Type: REG_DWORD
Value: 1

Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\16.0\Common\Identity
Name: EnableADAL
Type: REG_DWORD
Value: 1

Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\16.0\Common\Identity
Name: Version
Type: REG_DWORD
Value: 1
```

## Phase 4: Client Configuration

### Step 10: Update Client Machines

Run the client configuration script:

```powershell
# Deploy client-side fixes
.\scripts\configure-client.ps1 -ApplyRegistryFix -ConfigureTrustedSites -RestartServices
```

### Step 11: Clear Cached Credentials

```powershell
# Clear cached credentials on client machines
cmdkey /list | ForEach-Object {
    if ($_ -like "*login.microsoftonline.com*" -or $_ -like "*office365.com*") {
        $target = ($_ -split " ")[1]
        cmdkey /delete:$target
    }
}

# Clear Office credentials
Get-ChildItem "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
```

## Phase 5: Validation and Testing

### Step 12: Test Authentication Flow

1. **Test Domain Authentication:**
   ```powershell
   # Verify domain login
   whoami /upn
   nltest /dsgetdc:domain.local
   ```

2. **Test Azure AD Authentication:**
   ```powershell
   # Test Azure AD connectivity
   Test-NetConnection login.microsoftonline.com -Port 443
   ```

3. **Test Office Applications:**
   - Open Outlook, Word, Excel, PowerPoint
   - Verify no additional credential prompts
   - Check authentication in File → Account

### Step 13: Validate SSO Functionality

```powershell
# Run comprehensive validation
.\scripts\validate-setup.ps1 -TestAllComponents -GenerateReport
```

## Phase 6: Rollout and Monitoring

### Step 14: Staged Deployment

1. **Pilot Group (10-20 users):**
   - Deploy to IT team first
   - Monitor for 1 week
   - Collect feedback

2. **Department Rollout (50-100 users):**
   - Deploy to one department
   - Monitor for 2 weeks
   - Refine based on issues

3. **Organization-wide Deployment:**
   - Deploy to remaining users
   - Provide user communication
   - Monitor help desk tickets

### Step 15: Post-Implementation Monitoring

Set up monitoring for:
- Authentication failure rates
- Help desk ticket volume
- User satisfaction surveys
- System performance metrics

## Rollback Procedures

If issues arise, follow the rollback procedure:

```powershell
# Run rollback script
.\scripts\rollback.ps1 -RestoreBackups -RevertChanges
```

**Manual Rollback Steps:**
1. Restore Azure AD Connect configuration from backup
2. Restore Group Policy settings
3. Remove client-side registry changes
4. Clear Office credential cache

## Network Requirements

Ensure the following URLs are accessible:

### Required URLs
- `*.login.microsoftonline.com`
- `*.login.windows.net`
- `*.login.live.com`
- `*.office365.com`
- `*.outlook.office365.com`
- `*.protection.office365.com`

### Ports Required
- **443 (HTTPS)**: All authentication traffic
- **80 (HTTP)**: Redirects and some legacy endpoints

## Troubleshooting

For common issues and their solutions, see [troubleshooting.md](troubleshooting.md).

## Support and Documentation

- **Microsoft Documentation**: [Azure AD Seamless SSO](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-sso)
- **Office 365 Authentication**: [Modern Authentication](https://docs.microsoft.com/en-us/microsoft-365/enterprise/modern-auth-for-office-2013-and-2016)
- **Azure AD Connect**: [Installation Guide](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-install-roadmap)

## Next Steps

After successful implementation:
1. Run the [testing procedures](testing-procedures.md)
2. Monitor authentication logs for anomalies
3. Collect user feedback for continuous improvement
4. Plan regular review cycles for configuration maintenance