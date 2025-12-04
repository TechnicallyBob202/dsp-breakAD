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
    
    $domainNetBIOS = $Environment.Domain.NetBIOSName
    
    Write-Log "" -Level INFO
    Write-Log "=== MODULE 06: Group Policy Security ===" -Level INFO
    Write-Log "" -Level INFO
    
    # Modify Default Domain Policy settings
    Write-Log "Modifying Default Domain Policy..." -Level WARNING
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Set weak password settings
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
                    -ValueName "StrictSecurityChannelRequirement" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                Write-Log "  [+] Disabled strict security channel requirement" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error modifying Default Domain Policy: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Grant bad actors permissions on GPOs
    Write-Log "Granting bad actors permissions on GPOs..." -Level WARNING
    try {
        $gpos = Get-GPO -All -ErrorAction SilentlyContinue
        $badActor110 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`110" } -ErrorAction SilentlyContinue
        
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
        
        Write-Log "  [+] Granted bad actors permissions on $grantCount GPOs" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable audit policies
    Write-Log "Disabling security audit policies..." -Level WARNING
    try {
        # These would typically be set via auditpol command or Group Policy
        Write-Log "  [!] Audit policy changes require elevated registry/auditpol access - skipped" -Level WARNING
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Configure weak password policy via GPO
    Write-Log "Configuring weak password policies..." -Level WARNING
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
                
                Write-Log "  [+] Configured weak password policies" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error configuring password policies: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Modify UAC settings via GPO
    Write-Log "Modifying UAC settings..." -Level WARNING
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Disable UAC
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                    -ValueName "EnableLUA" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Disabled UAC via Group Policy" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error modifying UAC: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable Windows Defender via GPO
    Write-Log "Disabling security software policies..." -Level WARNING
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Disable Windows Defender
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows Defender" `
                    -ValueName "DisableAntiSpyware" -Value 1 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Disabled Windows Defender via Group Policy" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error disabling Defender: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Configure dangerous account lockout settings
    Write-Log "Configuring dangerous account lockout settings..." -Level WARNING
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
                
                Write-Log "  [+] Configured weak account lockout settings" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error configuring lockout: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Enable guest account via GPO
    Write-Log "Enabling guest account access..." -Level WARNING
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                # Enable null session access
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                    -ValueName "RestrictAnonymous" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Enabled null session access" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error enabling guest access: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable SMB signing
    Write-Log "Disabling SMB signing..." -Level WARNING
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
                    -ValueName "RequireSecuritySignature" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
                    -ValueName "RequireSecuritySignature" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Disabled SMB signing via Group Policy" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error disabling SMB signing: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Modify PowerShell execution policy via GPO
    Write-Log "Modifying PowerShell execution policy..." -Level WARNING
    try {
        $defaultPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultPolicy) {
            try {
                Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell" `
                    -ValueName "ExecutionPolicy" -Value "Unrestricted" -Type String -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Set PowerShell execution policy to Unrestricted" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error setting execution policy: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    Write-Log "Module 06 completed" -Level SUCCESS
    Write-Log "" -Level INFO
}

Export-ModuleMember -Function Invoke-ModuleGroupPolicySecurity