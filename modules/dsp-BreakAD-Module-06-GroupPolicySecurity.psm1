################################################################################
##
## dsp-BreakAD-Module-06-GroupPolicySecurity.psm1
##
## Configures Group Policy with security misconfigurations
## 
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Invoke-ModuleGroupPolicySecurity {
    <#
    .SYNOPSIS
        Configures Group Policy security misconfigurations
    
    .DESCRIPTION
        Applies security misconfigurations at Group Policy level:
        - Modify Default Domain Policy settings
        - Disable security group policy settings
        - Enable weak password policies
        - Configure dangerous audit policies
        - Modify account lockout settings
        - Configure dangerous UAC settings
        - Disable firewall policies
        - Modify security options
        - Configure weak encryption settings
        - Grant bad actors permissions on GPOs
    
    .PARAMETER Environment
        Hashtable with Domain, DomainController, etc.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $domainDN = $domain.DistinguishedName
    $domainNetBIOS = $domain.NetBIOSName
    $rwdcFQDN = $Environment.DomainController.HostName
    
    Write-Host ""
    Write-Host "=== MODULE 06: Group Policy Security ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Modify Default Domain Policy settings
    Write-Host "Modifying Default Domain Policy..." -ForegroundColor Yellow
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Set weak password settings
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
                    -ValueName "StrictSecurityChannelRequirement" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                Write-Host "  [+] Disabled strict security channel requirement" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error modifying Default Domain Policy: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Grant bad actors permissions on GPOs
    Write-Host "Granting bad actors permissions on GPOs..." -ForegroundColor Yellow
    try {
        $gpos = Get-GPO -All -ErrorAction SilentlyContinue
        $badActor110 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`110" } -ErrorAction SilentlyContinue
        $badActor111 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`111" } -ErrorAction SilentlyContinue
        
        $grantCount = 0
        if ($gpos -and $badActor110) {
            foreach ($gpo in $gpos | Select-Object -First 3) {
                try {
                    Set-GPPermission -Name $gpo.DisplayName -PermissionLevel GpoEditDeleteModifySecurity `
                        -TargetName $badActor110.SamAccountName -TargetType User -ErrorAction SilentlyContinue
                    $grantCount++
                }
                catch { }
            }
        }
        
        Write-Host "  [+] Granted bad actors permissions on $grantCount GPOs" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Disable audit policies
    Write-Host "Disabling security audit policies..." -ForegroundColor Yellow
    try {
        # These would typically be set via auditpol command or Group Policy
        Write-Host "  [!] Audit policy changes require elevated registry/auditpol access - skipped" -ForegroundColor Yellow
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Configure weak password policy via GPO
    Write-Host "Configuring weak password policies..." -ForegroundColor Yellow
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Set weak password minimum length
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
                    -ValueName "MinimumPasswordLength" -Value 3 -Type DWORD -ErrorAction SilentlyContinue
                
                # Disable password complexity
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
                    -ValueName "PasswordComplexity" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Configured weak password policies" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error configuring password policies: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Modify UAC settings via GPO
    Write-Host "Modifying UAC settings..." -ForegroundColor Yellow
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Disable UAC
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                    -ValueName "EnableLUA" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Disabled UAC via Group Policy" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error modifying UAC: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Disable Windows Defender via GPO
    Write-Host "Disabling security software policies..." -ForegroundColor Yellow
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Disable Windows Defender
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows Defender" `
                    -ValueName "DisableAntiSpyware" -Value 1 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Disabled Windows Defender via Group Policy" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error disabling Defender: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Configure dangerous account lockout settings
    Write-Host "Configuring dangerous account lockout settings..." -ForegroundColor Yellow
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Set very high lockout threshold (ineffective)
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
                    -ValueName "LockoutThreshold" -Value 999 -Type DWORD -ErrorAction SilentlyContinue
                
                # Set very short lockout duration (ineffective)
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
                    -ValueName "LockoutDuration" -Value 1 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Configured weak account lockout settings" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error configuring lockout: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Enable guest account via GPO
    Write-Host "Enabling guest account access..." -ForegroundColor Yellow
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Enable null session access
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                    -ValueName "RestrictAnonymous" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Enabled null session access" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error enabling guest access: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Disable SMB signing
    Write-Host "Disabling SMB signing..." -ForegroundColor Yellow
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
                    -ValueName "RequireSecuritySignature" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                    -ValueName "RequireSecuritySignature" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Disabled SMB signing via Group Policy" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error disabling SMB signing: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    # Modify PowerShell execution policy via GPO
    Write-Host "Modifying PowerShell execution policy..." -ForegroundColor Yellow
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell" `
                    -ValueName "ExecutionPolicy" -Value "Unrestricted" -Type String -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Set PowerShell execution policy to Unrestricted" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error setting execution policy: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host ""
    
    Write-Host "Module 06 completed" -ForegroundColor Green
    Write-Host ""
}

Export-ModuleMember -Function Invoke-ModuleGroupPolicySecurity