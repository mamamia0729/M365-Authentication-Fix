# Troubleshooting Guide

## Common Issues and Solutions

### Issue 1: Office Applications Still Prompting for Credentials

**Symptoms:**
- Office applications (Outlook, Word, Excel) repeatedly ask for username/password
- Authentication succeeds but prompts reappear within hours or days
- Different Office apps show different authentication behaviors

**Diagnosis Steps:**
1. Check if Modern Authentication is enabled:
   ```powershell
   Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Identity" -Name "EnableADAL"
   ```

2. Verify trusted sites configuration:
   ```powershell
   .\scripts\validate-setup.ps1 -QuickTest
   ```

3. Check credential cache:
   ```powershell
   cmdkey /list | findstr "office\|microsoft"
   ```

**Solutions:**
1. **Enable Modern Authentication:**
   ```powershell
   .\scripts\configure-client.ps1 -ApplyRegistryFix
   ```

2. **Clear credential cache:**
   ```powershell
   .\scripts\configure-client.ps1 -ClearCredentialCache
   ```

3. **Reset Office authentication:**
   ```powershell
   # Remove Office identity cache
   Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities" -Recurse -Force -ErrorAction SilentlyContinue
   ```

4. **Verify UPN configuration:**
   ```powershell
   whoami /upn
   # Should match your email address format
   ```

---

### Issue 2: Browser Authentication Not Working

**Symptoms:**
- Browser prompts for credentials when accessing Office 365 portal
- Integrated Windows Authentication not functioning
- Different behavior in different browsers

**Diagnosis Steps:**
1. Test trusted sites configuration:
   ```powershell
   $sites = @("login.microsoftonline.com", "portal.office.com")
   foreach ($site in $sites) {
       $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($site -split '\.' | Select-Object -First 1)\$($site -split '\.' -join '\')"
       if (Test-Path $path) {
           Write-Host "✅ $site configured" -ForegroundColor Green
       } else {
           Write-Host "❌ $site missing" -ForegroundColor Red
       }
   }
   ```

2. Check Internet Explorer security zones:
   ```powershell
   Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name "1A00"
   # Should be 0 for automatic logon
   ```

**Solutions:**
1. **Configure trusted sites:**
   ```powershell
   .\scripts\configure-client.ps1 -ConfigureTrustedSites
   ```

2. **Manual trusted sites configuration:**
   - Open Internet Explorer
   - Go to Tools → Internet Options → Security
   - Select "Trusted sites" → Sites
   - Add: `https://*.microsoftonline.com`, `https://*.office365.com`

3. **Enable Integrated Windows Authentication:**
   - Internet Options → Advanced → Security
   - Check "Enable Integrated Windows Authentication"

---

### Issue 3: Azure AD Connect Synchronization Problems

**Symptoms:**
- Password changes not syncing between on-premises and cloud
- UPN mismatches between systems
- Authentication works sometimes but not consistently

**Diagnosis Steps:**
1. Check Azure AD Connect status:
   ```powershell
   # On Azure AD Connect server
   Get-ADSyncScheduler
   Get-ADSyncConnectorRunStatus
   ```

2. Verify UPN consistency:
   ```powershell
   # Compare on-premises and Azure AD UPNs
   $onPremUPN = (Get-ADUser $env:USERNAME).UserPrincipalName
   Write-Host "On-premises UPN: $onPremUPN"
   ```

**Solutions:**
1. **Force Azure AD Connect sync:**
   ```powershell
   # On Azure AD Connect server
   Start-ADSyncSyncCycle -PolicyType Delta
   ```

2. **Fix UPN mismatches:**
   ```powershell
   # Update on-premises UPN to match Azure AD
   Set-ADUser -Identity $username -UserPrincipalName "user@domain.com"
   ```

3. **Enable Password Hash Sync:**
   - Run Azure AD Connect wizard
   - Select "Change user sign-in"
   - Enable "Password Hash Synchronization"

---

### Issue 4: Network Connectivity Problems

**Symptoms:**
- Authentication timeouts
- Intermittent connection failures
- Different behavior on different networks

**Diagnosis Steps:**
1. Test M365 endpoints:
   ```powershell
   $endpoints = @(
       "login.microsoftonline.com:443",
       "outlook.office365.com:443",
       "graph.microsoft.com:443"
   )
   
   foreach ($endpoint in $endpoints) {
       $url, $port = $endpoint -split ":"
       $result = Test-NetConnection -ComputerName $url -Port $port
       Write-Host "$endpoint : $($result.TcpTestSucceeded)"
   }
   ```

2. Check DNS resolution:
   ```powershell
   nslookup login.microsoftonline.com
   ```

3. Test from different locations:
   ```powershell
   # Test from command prompt
   curl -I https://login.microsoftonline.com
   ```

**Solutions:**
1. **Configure firewall rules:**
   - Allow outbound HTTPS (443) to Microsoft endpoints
   - Add specific URLs to firewall exceptions

2. **Update DNS settings:**
   - Use public DNS (8.8.8.8, 1.1.1.1) for testing
   - Check corporate DNS for Microsoft endpoints

3. **Proxy configuration:**
   ```powershell
   # Check current proxy settings
   netsh winhttp show proxy
   
   # Configure proxy bypass for Microsoft endpoints
   netsh winhttp set proxy proxy-server="your-proxy:8080" bypass-list="*.microsoftonline.com;*.office365.com"
   ```

---

### Issue 5: Group Policy Not Applying

**Symptoms:**
- Registry settings not appearing on client machines
- Inconsistent authentication behavior across machines
- New machines not getting correct configuration

**Diagnosis Steps:**
1. Check Group Policy application:
   ```powershell
   gpresult /r
   gpupdate /force
   ```

2. Verify registry settings:
   ```powershell
   .\scripts\validate-setup.ps1 -TestAllComponents
   ```

3. Check event logs:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-GroupPolicy/Operational" -MaxEvents 10
   ```

**Solutions:**
1. **Force Group Policy update:**
   ```powershell
   gpupdate /force
   shutdown /r /t 0
   ```

2. **Check Group Policy scope:**
   - Verify OU structure
   - Check security filtering
   - Confirm WMI filters (if used)

3. **Manual registry deployment:**
   ```powershell
   # Import registry file directly
   reg import "examples\registry-settings.reg"
   ```

---

## Advanced Troubleshooting

### Enable Detailed Logging

1. **Office Authentication Logs:**
   ```powershell
   # Enable Office authentication logging
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Logging" -Name "EnableLogging" -Value 1
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Logging" -Name "LogLevel" -Value 1
   ```

2. **Windows Authentication Logs:**
   ```powershell
   # Enable detailed authentication logging
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   ```

3. **Azure AD Connect Logs:**
   - Check Event Viewer → Applications and Services Logs → Azure AD Connect
   - Review synchronization logs in Azure AD portal

### Performance Analysis

1. **Authentication timing:**
   ```powershell
   Measure-Command {
       Test-NetConnection login.microsoftonline.com -Port 443
   }
   ```

2. **Network latency:**
   ```powershell
   ping login.microsoftonline.com -t
   tracert login.microsoftonline.com
   ```

### Recovery Procedures

1. **Complete reset:**
   ```powershell
   # Clear all cached credentials
   .\scripts\configure-client.ps1 -ClearCredentialCache
   
   # Reset Office authentication
   Remove-Item "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -Recurse -Force
   
   # Restart relevant services
   Restart-Service Themes, Browser -Force
   ```

2. **Rollback to previous state:**
   ```powershell
   .\scripts\rollback.ps1 -RestoreBackups -RevertChanges
   ```

## Getting Help

### Log Collection for Support

```powershell
# Collect comprehensive diagnostic information
.\scripts\diagnostics.ps1 -Detailed -ExportPath "C:\Support\M365-Diagnostics.html"

# Export event logs
wevtutil epl System C:\Support\System.evtx
wevtutil epl Application C:\Support\Application.evtx
wevtutil epl Security C:\Support\Security.evtx
```

### Escalation Path

1. **Level 1**: Run diagnostic script and check common issues
2. **Level 2**: Enable detailed logging and collect logs
3. **Level 3**: Contact Microsoft Support with diagnostic data

### Useful Microsoft Resources

- [Azure AD Connect troubleshooting](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/tshoot-connect-connectivity)
- [Office 365 authentication](https://docs.microsoft.com/en-us/microsoft-365/enterprise/modern-auth-for-office-2013-and-2016)
- [Microsoft 365 network connectivity](https://docs.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-networking-overview)

---

*This troubleshooting guide is continuously updated based on community feedback and common issues reported.*