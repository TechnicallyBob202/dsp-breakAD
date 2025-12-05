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
    
    $successCount = 0
    $errorCount = 0
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 07: Registry Security" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    # Disable NTLMv2 enforcement
    Write-Host "Disabling NTLMv2 enforcement..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regKey = "LmCompatibilityLevel"
        
        try {
            Set-ItemProperty -Path $regPath -Name $regKey -Value 3 -ErrorAction SilentlyContinue
            Write-Host "  [+] Set LmCompatibilityLevel to 3 (NTLMv2 optional)" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] Registry modification requires local admin on target system" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Enable LAN Manager hashing
    Write-Host "Enabling LAN Manager hashing..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regKey = "NoLmHash"
        
        try {
            Set-ItemProperty -Path $regPath -Name $regKey -Value 0 -ErrorAction SilentlyContinue
            Write-Host "  [+] Enabled LAN Manager hashing (NoLmHash = 0)" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] Registry modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Weaken Kerberos settings
    Write-Host "Weakening Kerberos settings..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        
        try {
            # Disable DES encryption check
            Set-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -Value 3 -ErrorAction SilentlyContinue
            Write-Host "  [+] Set SupportedEncryptionTypes to allow weak encryption" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] Kerberos registry modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Disable credential guard
    Write-Host "Disabling Credential Guard..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regKey = "LsaCfgFlags"
        
        try {
            Set-ItemProperty -Path $regPath -Name $regKey -Value 0 -ErrorAction SilentlyContinue
            Write-Host "  [+] Disabled Credential Guard (LsaCfgFlags = 0)" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] Credential Guard setting skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Weaken SMB settings
    Write-Host "Weakening SMB settings..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        
        try {
            # Disable SMB encryption
            Set-ItemProperty -Path $regPath -Name "EncryptionLevel" -Value 0 -ErrorAction SilentlyContinue
            # Enable null sessions
            Set-ItemProperty -Path $regPath -Name "NullSessionPipes" -Value "COMSPEC,SPOOL" -ErrorAction SilentlyContinue
            Write-Host "  [+] Weakened SMB encryption and session settings" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] SMB setting modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Disable null session restrictions
    Write-Host "Disabling null session restrictions..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        try {
            Set-ItemProperty -Path $regPath -Name "RestrictAnonymous" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regPath -Name "EveryoneIncludesAnonymous" -Value 1 -ErrorAction SilentlyContinue
            Write-Host "  [+] Disabled null session restrictions" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] Null session setting modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Enable anonymous enumeration
    Write-Host "Enabling anonymous enumeration..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        try {
            Set-ItemProperty -Path $regPath -Name "RestrictAnonymousSam" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $regPath -Name "RestrictAnonymousNetBios" -Value 0 -ErrorAction SilentlyContinue
            Write-Host "  [+] Enabled anonymous SAM and NetBIOS enumeration" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] Anonymous enumeration setting modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Configure dangerous WinRM settings
    Write-Host "Configuring dangerous WinRM settings..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
        
        try {
            Set-ItemProperty -Path $regPath -Name "AllowUnencryptedTraffic" -Value 1 -ErrorAction SilentlyContinue
            Write-Host "  [+] Enabled unencrypted WinRM traffic" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] WinRM setting modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Disable LSA protection
    Write-Host "Disabling LSA protection..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $regKey = "RunAsPPL"
        
        try {
            Set-ItemProperty -Path $regPath -Name $regKey -Value 0 -ErrorAction SilentlyContinue
            Write-Host "  [+] Disabled LSA protection (RunAsPPL = 0)" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] LSA protection setting modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Disable MitigationOptions (Control Flow Guard and others)
    Write-Host "Disabling security mitigations..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
        
        try {
            Set-ItemProperty -Path $regPath -Name "MitigationOptions" -Value 0 -ErrorAction SilentlyContinue
            Write-Host "  [+] Disabled security mitigations" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] Mitigation options setting modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Weaken RPC security
    Write-Host "Weakening RPC security..." -ForegroundColor Yellow
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
        
        try {
            Set-ItemProperty -Path $regPath -Name "EnableAuthEpResolution" -Value 0 -ErrorAction SilentlyContinue
            Write-Host "  [+] Weakened RPC authentication endpoint resolution" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  [!] RPC security setting modification skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    Write-Host "Module 07 completed" -ForegroundColor Green
    Write-Host "" -ForegroundColor Cyan
    
    if ($errorCount -gt $successCount) {
        return $false
    }
    return $true
}

Export-ModuleMember -Function Invoke-ModuleRegistrySecurity