################################################################################
##
## dsp-BreakAD-Module-00-Preflight.psm1
##
## Purpose: Preflight validation and setup for dsp-breakAD
##
## Validates:
## - Administrator rights
## - PowerShell version 5.1+
## - ActiveDirectory module available
## - AD domain connectivity
## - KDS root key exists (creates if missing - required for dMSA)
## - BreakAD OU structure
##
## Author: Bob (bob@semperis.com)
## Version: 1.0.1 (Added KDS root key check/creation)
##
################################################################################

function Invoke-ModulePreflight {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 00: Preflight Validation" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # ADMINISTRATOR RIGHTS CHECK
    ################################################################################
    
    Write-Log "  Checking administrator rights..." -Level INFO
    $isAdmin = [Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains [Security.Principal.SecurityIdentifier]"S-1-5-32-544"
    if ($isAdmin) {
        Write-Log "    [+] Running as administrator" -Level SUCCESS
    }
    else {
        Write-Log "    [!] Not running as administrator - script will fail" -Level ERROR
        return $false
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # POWERSHELL VERSION CHECK
    ################################################################################
    
    Write-Log "  Checking PowerShell version..." -Level INFO
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Write-Log "    [+] PowerShell $($PSVersionTable.PSVersion) (5.1+ required)" -Level SUCCESS
    }
    else {
        Write-Log "    [!] PowerShell $($PSVersionTable.PSVersion) - need 5.1+" -Level ERROR
        return $false
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # ACTIVEDIRECTORY MODULE CHECK
    ################################################################################
    
    Write-Log "  Loading ActiveDirectory module..." -Level INFO
    try {
        if (-not (Get-Module ActiveDirectory -ErrorAction SilentlyContinue)) {
            Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
            Write-Log "    [+] ActiveDirectory module imported" -Level SUCCESS
        }
        else {
            Write-Log "    [+] ActiveDirectory module already loaded" -Level SUCCESS
        }
    }
    catch {
        Write-Log "    [!] Failed to load ActiveDirectory module: $_" -Level ERROR
        return $false
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # AD CONNECTIVITY CHECK
    ################################################################################
    
    Write-Log "  Checking Active Directory connectivity..." -Level INFO
    try {
        $adTest = Get-ADDomain -ErrorAction Stop
        Write-Log "    [+] AD domain: $($adTest.Name)" -Level SUCCESS
    }
    catch {
        Write-Log "    [!] Failed to discover domain information: $_" -Level ERROR
        return $false
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # KDS ROOT KEY CHECK
    ################################################################################
    
    Write-Log "  Checking KDS root key (required for dMSA)..." -Level INFO
    try {
        $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue
        if ($kdsKey) {
            Write-Log "    [+] KDS root key exists: $($kdsKey.Guid)" -Level SUCCESS
        }
        else {
            Write-Log "    [*] KDS root key not found - creating..." -Level INFO
            $newKey = Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10)) -ErrorAction Stop
            Write-Log "    [+] KDS root key created: $($newKey.Guid)" -Level SUCCESS
        }
    }
    catch {
        Write-Log "    [!] Error with KDS root key: $_" -Level WARNING
        Write-Log "    [!] dMSA creation may fail - dMSA IOEs will be skipped" -Level WARNING
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # COMPLETION
    ################################################################################
    
    Write-Log "========================================" -Level INFO
    Write-Log "Module 00: Preflight Validation" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Status: COMPLETE" -Level SUCCESS
    Write-Log "" -Level INFO
    
    return $true
}

Export-ModuleMember -Function Invoke-ModulePreflight