################################################################################
##
## dsp-BreakAD-Module-01-Verify.ps1
##
## Verification script for Module 01 Group Policy Security IOEs
## Checks if all configurations were actually applied
##
################################################################################

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Module 01 Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$domainFQDN = $domain.DNSRoot
$breakADOU = "OU=BreakAD,$domainDN"

$issues = @()
$verified = @()

# =====================================================================
# Check 1: Default Domain Policy modification
# =====================================================================
Write-Host "Check 1: Default Domain Policy registry values..." -ForegroundColor Yellow

try {
    $defDomPol = Get-GPO -Name "Default Domain Policy" -ErrorAction Stop
    $regValues = Get-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    
    if ($regValues | Where-Object { $_.ValueName -eq "SubmitControl" }) {
        Write-Host "  [+] SubmitControl registry value found" -ForegroundColor Green
        $verified += "Default Domain Policy - SubmitControl"
    }
    else {
        Write-Host "  [!] SubmitControl registry value NOT found" -ForegroundColor Red
        $issues += "Default Domain Policy missing SubmitControl registry value"
    }
}
catch {
    Write-Host "  [!] Error checking Default Domain Policy: $_" -ForegroundColor Red
    $issues += "Default Domain Policy check failed: $_"
}

# =====================================================================
# Check 2: Default Domain Controllers Policy modification
# =====================================================================
Write-Host "Check 2: Default Domain Controllers Policy registry values..." -ForegroundColor Yellow

try {
    $defDCPol = Get-GPO -Name "Default Domain Controllers Policy" -ErrorAction Stop
    $regValues = Get-GPRegistryValue -Name "Default Domain Controllers Policy" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    
    if ($regValues | Where-Object { $_.ValueName -eq "SubmitControl" }) {
        Write-Host "  [+] SubmitControl registry value found" -ForegroundColor Green
        $verified += "Default Domain Controllers Policy - SubmitControl"
    }
    else {
        Write-Host "  [!] SubmitControl registry value NOT found" -ForegroundColor Red
        $issues += "Default Domain Controllers Policy missing SubmitControl registry value"
    }
}
catch {
    Write-Host "  [!] Error checking Default Domain Controllers Policy: $_" -ForegroundColor Red
    $issues += "Default Domain Controllers Policy check failed: $_"
}

# =====================================================================
# Check 3: Test GPOs exist
# =====================================================================
Write-Host "Check 3: Test GPOs created..." -ForegroundColor Yellow

$testGPOs = @("breakAD-LinkTest-Domain", "breakAD-LinkTest-Site", "breakAD-LinkTest-OU")
foreach ($gpoName in $testGPOs) {
    try {
        $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
        Write-Host "  [+] $gpoName exists" -ForegroundColor Green
        $verified += "GPO: $gpoName"
    }
    catch {
        Write-Host "  [!] $gpoName NOT found" -ForegroundColor Red
        $issues += "Missing GPO: $gpoName"
    }
}

# =====================================================================
# Check 4: GPO linking at BreakAD OU
# =====================================================================
Write-Host "Check 4: GPO links on BreakAD OU..." -ForegroundColor Yellow

try {
    $ouObj = Get-ADOrganizationalUnit -Identity $breakADOU -ErrorAction Stop
    $gPLinks = $ouObj.LinkedGroupPolicyObjects
    
    if ($gPLinks.Count -gt 0) {
        Write-Host "  [+] Found $($gPLinks.Count) GPO link(s)" -ForegroundColor Green
        foreach ($link in $gPLinks) {
            Write-Host "      - $link" -ForegroundColor Cyan
        }
        $verified += "GPO links on BreakAD OU: $($gPLinks.Count) link(s)"
    }
    else {
        Write-Host "  [!] No GPO links found on BreakAD OU" -ForegroundColor Red
        $issues += "No GPO links on BreakAD OU"
    }
}
catch {
    Write-Host "  [!] Error checking BreakAD OU: $_" -ForegroundColor Red
    $issues += "Failed to check BreakAD OU: $_"
}

# =====================================================================
# Check 5: Dangerous user rights in breakAD-LinkTest-OU
# =====================================================================
Write-Host "Check 5: Registry values in breakAD-LinkTest-OU GPO..." -ForegroundColor Yellow

try {
    $regValues = Get-GPRegistryValue -Name "breakAD-LinkTest-OU" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    
    if ($regValues | Where-Object { $_.ValueName -eq "EnableCursorSuppression" }) {
        Write-Host "  [+] EnableCursorSuppression found" -ForegroundColor Green
        $verified += "GPO registry: EnableCursorSuppression"
    }
    else {
        Write-Host "  [!] EnableCursorSuppression NOT found" -ForegroundColor Red
        $issues += "Missing EnableCursorSuppression in breakAD-LinkTest-OU"
    }
}
catch {
    Write-Host "  [!] Error checking registry values: $_" -ForegroundColor Red
    $issues += "Failed to check registry values: $_"
}

# =====================================================================
# Check 6: Logon script path in breakAD-LinkTest-OU
# =====================================================================
Write-Host "Check 6: Logon script path in breakAD-LinkTest-OU..." -ForegroundColor Yellow

try {
    $regValues = Get-GPRegistryValue -Name "breakAD-LinkTest-OU" -Key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    
    if ($regValues | Where-Object { $_.ValueName -eq "UserInitMprLogonScript" }) {
        $value = ($regValues | Where-Object { $_.ValueName -eq "UserInitMprLogonScript" }).Value
        Write-Host "  [+] UserInitMprLogonScript found: $value" -ForegroundColor Green
        $verified += "GPO registry: UserInitMprLogonScript = $value"
    }
    else {
        Write-Host "  [!] UserInitMprLogonScript NOT found" -ForegroundColor Red
        $issues += "Missing UserInitMprLogonScript in breakAD-LinkTest-OU"
    }
}
catch {
    Write-Host "  [!] Error checking logon script: $_" -ForegroundColor Red
    $issues += "Failed to check logon script: $_"
}

# =====================================================================
# Check 7: Reversible password storage in breakAD-LinkTest-OU
# =====================================================================
Write-Host "Check 7: Reversible password storage in breakAD-LinkTest-OU..." -ForegroundColor Yellow

try {
    $regValues = Get-GPRegistryValue -Name "breakAD-LinkTest-OU" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    
    if ($regValues | Where-Object { $_.ValueName -eq "NoLMHash" }) {
        $value = ($regValues | Where-Object { $_.ValueName -eq "NoLMHash" }).Value
        if ($value -eq 0) {
            Write-Host "  [+] NoLMHash = $value (reversible encryption enabled)" -ForegroundColor Green
            $verified += "GPO registry: NoLMHash = $value"
        }
        else {
            Write-Host "  [!] NoLMHash = $value (should be 0)" -ForegroundColor Red
            $issues += "NoLMHash incorrect value: $value"
        }
    }
    else {
        Write-Host "  [!] NoLMHash NOT found" -ForegroundColor Red
        $issues += "Missing NoLMHash in breakAD-LinkTest-OU"
    }
}
catch {
    Write-Host "  [!] Error checking reversible passwords: $_" -ForegroundColor Red
    $issues += "Failed to check reversible passwords: $_"
}

# =====================================================================
# Check 8: LM hash storage in breakAD-LinkTest-OU
# =====================================================================
Write-Host "Check 8: LM hash storage in breakAD-LinkTest-OU..." -ForegroundColor Yellow

try {
    $regValues = Get-GPRegistryValue -Name "breakAD-LinkTest-OU" -Key "HKLM\System\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    
    if ($regValues | Where-Object { $_.ValueName -eq "LMCompatibilityLevel" }) {
        $value = ($regValues | Where-Object { $_.ValueName -eq "LMCompatibilityLevel" }).Value
        if ($value -eq 2) {
            Write-Host "  [+] LMCompatibilityLevel = $value (weak LM hash enabled)" -ForegroundColor Green
            $verified += "GPO registry: LMCompatibilityLevel = $value"
        }
        else {
            Write-Host "  [!] LMCompatibilityLevel = $value (should be 2)" -ForegroundColor Red
            $issues += "LMCompatibilityLevel incorrect value: $value"
        }
    }
    else {
        Write-Host "  [!] LMCompatibilityLevel NOT found" -ForegroundColor Red
        $issues += "Missing LMCompatibilityLevel in breakAD-LinkTest-OU"
    }
}
catch {
    Write-Host "  [!] Error checking LM hash: $_" -ForegroundColor Red
    $issues += "Failed to check LM hash: $_"
}

# =====================================================================
# Check 9: GPO delegation user
# =====================================================================
Write-Host "Check 9: GPO delegation user (break-gpo-delegate)..." -ForegroundColor Yellow

try {
    $delUser = Get-ADUser -Filter { SamAccountName -eq "break-gpo-delegate" } -ErrorAction Stop
    Write-Host "  [+] Delegation user exists: $($delUser.Name)" -ForegroundColor Green
    $verified += "Delegation user: $($delUser.Name)"
}
catch {
    Write-Host "  [!] Delegation user NOT found" -ForegroundColor Red
    $issues += "Missing delegation user: break-gpo-delegate"
}

# =====================================================================
# Check 10: ACL delegation on BreakAD OU
# =====================================================================
Write-Host "Check 10: ACL delegation on BreakAD OU..." -ForegroundColor Yellow

try {
    $acl = Get-Acl "AD:$breakADOU"
    $linkGPOGUID = "01814787-5BB5-42d3-A4D5-0595BC1DD92A"
    
    $linkGPOAces = $acl.Access | Where-Object { 
        $_.ObjectType -eq $linkGPOGUID -and 
        $_.ActiveDirectoryRights -like "*Write*"
    }
    
    if ($linkGPOAces) {
        Write-Host "  [+] Found $($linkGPOAces.Count) LinkGPO ACE(s)" -ForegroundColor Green
        foreach ($ace in $linkGPOAces) {
            Write-Host "      - $($ace.IdentityReference)" -ForegroundColor Cyan
        }
        $verified += "LinkGPO ACEs: $($linkGPOAces.Count)"
    }
    else {
        Write-Host "  [!] No LinkGPO ACEs found" -ForegroundColor Red
        $issues += "No LinkGPO delegation ACEs on BreakAD OU"
    }
}
catch {
    Write-Host "  [!] Error checking ACL: $_" -ForegroundColor Red
    $issues += "Failed to check ACL: $_"
}

# =====================================================================
# Summary
# =====================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Verified ($($verified.Count)):" -ForegroundColor Green
foreach ($item in $verified) {
    Write-Host "  [+] $item" -ForegroundColor Green
}

Write-Host ""

if ($issues.Count -gt 0) {
    Write-Host "Issues ($($issues.Count)):" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "  [!] $issue" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Total Issues: $($issues.Count)" -ForegroundColor Red
}
else {
    Write-Host "No issues found!" -ForegroundColor Green
}

Write-Host ""
Write-Host "Note: Even if all checks pass, DSP may not detect IOEs immediately." -ForegroundColor Yellow
Write-Host "      Ensure Group Policy has been updated with 'gpupdate /force'" -ForegroundColor Yellow
Write-Host ""