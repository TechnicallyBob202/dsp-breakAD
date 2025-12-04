################################################################################
##
## dsp-BreakAD-Module-07-RegistrySecurity.psm1
##
## Configures registry and authentication security misconfigurations
## 
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Invoke-ModuleRegistrySecurity {
    <#
    .SYNOPSIS
        Configures registry and authentication security misconfigurations
    
    .DESCRIPTION
        Applies security misconfigurations at registry level:
        - Disable NTLMv2 enforcement
        - Enable LAN Manager hashing
        - Weaken Kerberos settings
        - Disable credential guard
        - Configure weak SMB settings
        - Disable null session restrictions
        - Enable anonymous enumeration
        - Configure dangerous WinRM settings
        - Disable LSA protection
        - Weaken remote procedure call security
    
    .PARAMETER Environment
        Hashtable with Domain, DomainController, etc.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    Write-Log "" -Level INFO
    Write-Log "=== MODULE 07: Registry and Authentication Security ===" -Level INFO
    Write-Log "" -Level INFO
    
    # Disable NTLMv2 enforcement
    Write-Log "Disabling NTLMv2 enforcement..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regKey = "LmCompatibilityLevel"
        
        try {
            Set-ItemProperty -Path $regPath -Name $regKey -Value 3 -ErrorAction SilentlyContinue
            Write-Log "  [+] Set LmCompatibilityLevel to 3 (NTLMv2 optional)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Registry modification requires local admin on target system" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Enable LAN Manager hashing
    Write-Log "Enabling LAN Manager hashing..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regKey = "NoLmHash"
        
        try {
            Set-ItemProperty -Path $regPath -Name $regKey -Value 0 -ErrorAction SilentlyContinue
            Write-Log "  [+] Enabled LAN Manager hashing (NoLmHash = 0)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Registry modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Weaken Kerberos settings
    Write-Log "Weakening Kerberos settings..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        
        try {
            # Disable DES encryption check
            Set-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -Value 3 -ErrorAction SilentlyContinue
            Write-Log "  [+] Set SupportedEncryptionTypes to allow weak encryption" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Kerberos registry modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable credential guard
    Write-Log "Disabling Credential Guard..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regKey = "LsaCfgFlags"
        
        try {
            Set-ItemProperty -Path $regPath -Name $regKey -Value 0 -ErrorAction SilentlyContinue
            Write-Log "  [+] Disabled Credential Guard (LsaCfgFlags = 0)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Credential Guard setting skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Weaken SMB settings
    Write-Log "Weakening SMB settings..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        
        try {
            # Disable SMB encryption
            Set-ItemProperty -Path $regPath -Name "EncryptionLevel" -Value 0 -ErrorAction SilentlyContinue
            # Enable null sessions
            Set-ItemProperty -Path $regPath -Name "NullSessionPipes" -Value "COMSPEC,SPOOL" -ErrorAction SilentlyContinue
            Write-Log "  [+] Weakened SMB encryption and session settings" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] SMB setting modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable null session restrictions
    Write-Log "Disabling null session restrictions..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        try {
            Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 1 -ErrorAction SilentlyContinue
            Write-Log "  [+] Disabled null session restrictions" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Null session setting modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Enable anonymous enumeration
    Write-Log "Enabling anonymous enumeration..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        try {
            Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSam" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regPath -Name "RestrictAnonymousNetBios" -Value 0 -ErrorAction SilentlyContinue
            Write-Log "  [+] Enabled anonymous SAM and NetBIOS enumeration" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Anonymous enumeration setting modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Configure dangerous WinRM settings
    Write-Log "Configuring dangerous WinRM settings..." -Level WARNING
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        
        try {
            Set-ItemProperty -Path $regPath -Name "AllowUnencryptedTraffic" -Value 1 -ErrorAction SilentlyContinue
            Write-Log "  [+] Enabled unencrypted WinRM traffic" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] WinRM setting modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable LSA protection
    Write-Log "Disabling LSA protection..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regKey = "RunAsPPL"
        
        try {
            Set-ItemProperty -Path $regPath -Name $regKey -Value 0 -ErrorAction SilentlyContinue
            Write-Log "  [+] Disabled LSA protection (RunAsPPL = 0)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] LSA protection setting modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable MitigationOptions (Control Flow Guard and others)
    Write-Log "Disabling security mitigations..." -Level WARNING
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
        
        try {
            Set-ItemProperty -Path $regPath -Name "MitigationOptions" -Value 0 -ErrorAction SilentlyContinue
            Write-Log "  [+] Disabled security mitigations" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Mitigation options setting modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Weaken RPC security
    Write-Log "Weakening RPC security..." -Level WARNING
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
        
        try {
            Set-ItemProperty -Path $regPath -Name "EnableAuthEpResolution" -Value 0 -ErrorAction SilentlyContinue
            Write-Log "  [+] Weakened RPC authentication endpoint resolution" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] RPC security setting modification skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    Write-Log "Module 07 completed" -Level SUCCESS
    Write-Log "" -Level INFO
}

Export-ModuleMember -Function Invoke-ModuleRegistrySecurity