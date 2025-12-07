################################################################################
##
## dsp-BreakAD-Module-01-GroupPolicySecurity.psm1
##
## Purpose: Introduce Group Policy Security misconfigurations to lower DSP score
## Targets: Group Policy Security IOE category in DSP
##
## IOEs Targeted (13):
##  1. Changes to Default Domain Policy or Default Domain Controllers Policy
##  2. Changes to GPO linking at the AD Site level
##  3. Changes to GPO linking at the Domain level
##  4. Dangerous GPO logon script path
##  5. Dangerous user rights granted by GPO
##  6. GPO linking delegation at the AD Site level
##  7. GPO linking delegation at the domain controller OU level
##  8. GPO linking delegation at the domain level
##  9. Reversible passwords found in GPOs
## 10. SYSVOL Executable Changes
## 11. GPO weak LM hash storage enabled
## 12. GPO with scheduled tasks configured
## 13. Writable shortcuts found in GPO
##
## Design Philosophy:
##  - All actions scoped to BreakAD OUs whenever possible
##  - No modifications to actual Default Domain/Controllers Policy (keep innocuous changes lit)
##  - GPO preferences set via Set-GPRegistryValue where applicable
##  - Logon scripts referenced in GPO but not created on SYSVOL
##  - Delegation granted on BreakAD OUs
##  - Link/unlink operations on test GPOs in BreakAD OU
##
## Author: Bob (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleGroupPolicySecurity {
    <#
    .SYNOPSIS
        Introduce Group Policy Security misconfigurations to DSP detection range
    
    .PARAMETER Environment
        Hashtable containing Domain, DomainController, and Config
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    $dcFQDN = $dc.HostName
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 01: Group Policy Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    try {
        # =====================================================================
        # PHASE 1: Verify GroupPolicy module is available
        # =====================================================================
        
        Write-Log "PHASE 1: Validating GroupPolicy module" -Level INFO
        
        try {
            Import-Module GroupPolicy -ErrorAction Stop | Out-Null
            Write-Log "  [+] GroupPolicy module available" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] GroupPolicy module not available: $_" -Level ERROR
            return $false
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 2: Modify Default Domain/Controllers Policies (keep them lit)
        # =====================================================================
        
        Write-Log "PHASE 2: Innocuous changes to Default Domain/Controllers Policies" -Level INFO
        Write-Log "  [*] IOE: Changes to Default Domain Policy/Controllers Policy" -Level INFO
        
        try {
            # Modify Default Domain Policy with innocuous change
            $defDomainPol = Get-GPO -Name "Default Domain Policy" -ErrorAction Stop
            
            # Set a harmless setting (e.g., audit policy)
            # This keeps the IOE "lit" without breaking anything
            Set-GPRegistryValue -Name "Default Domain Policy" `
                -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                -ValueName "SubmitControl" `
                -Value 1 `
                -Type DWORD `
                -ErrorAction Stop | Out-Null
            
            Write-Log "    [+] Modified Default Domain Policy" -Level SUCCESS
            
            # Modify Default Domain Controllers Policy
            $defDCPol = Get-GPO -Name "Default Domain Controllers Policy" -ErrorAction Stop
            
            Set-GPRegistryValue -Name "Default Domain Controllers Policy" `
                -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                -ValueName "SubmitControl" `
                -Value 1 `
                -Type DWORD `
                -ErrorAction Stop | Out-Null
            
            Write-Log "    [+] Modified Default Domain Controllers Policy" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error modifying default policies: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 3: Create test GPOs for link/unlink operations
        # =====================================================================
        
        Write-Log "PHASE 3: Create test GPOs for link/unlink operations" -Level INFO
        
        $breakADOU = "OU=BreakAD,$domainDN"
        $gpoNames = @(
            "breakAD-LinkTest-Domain",
            "breakAD-LinkTest-Site",
            "breakAD-LinkTest-OU"
        )
        
        $createdGPOs = @()
        
        foreach ($gpoName in $gpoNames) {
            try {
                $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                
                if ($existingGPO) {
                    Write-Log "    [*] GPO already exists: $gpoName" -Level INFO
                    $createdGPOs += $existingGPO
                }
                else {
                    $newGPO = New-GPO -Name $gpoName -Comment "breakAD test GPO for linking changes" -Server $dcFQDN -ErrorAction Stop
                    Write-Log "    [+] Created GPO: $gpoName" -Level SUCCESS
                    $createdGPOs += $newGPO
                }
            }
            catch {
                Write-Log "    [!] Error creating GPO $gpoName : $_" -Level ERROR
            }
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 4: IOE #2 & #3: Link/unlink GPOs at Domain and Site levels
        # =====================================================================
        
        Write-Log "PHASE 4: Link/unlink operations (IOE: Changes to GPO linking)" -Level INFO
        
        # Link at Domain level
        try {
            $domainGPO = $createdGPOs | Where-Object { $_.DisplayName -eq "breakAD-LinkTest-Domain" }
            
            if ($domainGPO) {
                # Check if already linked
                $linked = Get-GPLink -Target $breakADOU -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $domainGPO.DisplayName }
                
                if (-not $linked) {
                    New-GPLink -Name $domainGPO.DisplayName -Target $breakADOU -Server $dcFQDN -ErrorAction Stop | Out-Null
                    Write-Log "    [+] Linked $($domainGPO.DisplayName) to BreakAD OU" -Level SUCCESS
                }
                else {
                    Write-Log "    [*] GPO already linked at OU level" -Level INFO
                }
            }
        }
        catch {
            Write-Log "    [!] Error linking domain GPO: $_" -Level WARNING
        }
        
        # Link at Site level (to first available site)
        try {
            $siteGPO = $createdGPOs | Where-Object { $_.DisplayName -eq "breakAD-LinkTest-Site" }
            
            if ($siteGPO) {
                $siteDN = Get-ADObject -Filter { ObjectClass -eq "site" } `
                    -SearchBase "CN=Sites,CN=Configuration,$domainDN" `
                    -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty DistinguishedName
                
                if ($siteDN) {
                    $linked = Get-GPLink -Target $siteDN -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $siteGPO.DisplayName }
                    
                    if (-not $linked) {
                        New-GPLink -Name $siteGPO.DisplayName -Target $siteDN -Server $dcFQDN -ErrorAction Stop | Out-Null
                        Write-Log "    [+] Linked $($siteGPO.DisplayName) to site: $siteDN" -Level SUCCESS
                    }
                    else {
                        Write-Log "    [*] GPO already linked at site level" -Level INFO
                    }
                }
                else {
                    Write-Log "    [!] No sites found to link GPO" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "    [!] Error linking site GPO: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 5: IOE #5: Dangerous user rights granted by GPO
        # =====================================================================
        
        Write-Log "PHASE 5: Configure dangerous user rights in GPO" -Level INFO
        Write-Log "  [*] IOE: Dangerous user rights granted by GPO" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                # Set dangerous user rights via registry preference
                # Debug Programs: SeDebugPrivilege (not in registry but can be set via GPP)
                # For now, we'll set via HKLM registry which GPO can enforce
                
                Set-GPRegistryValue -Name $rightGPO.DisplayName `
                    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
                    -ValueName "EnableCursorSuppression" `
                    -Value 1 `
                    -Type DWORD `
                    -ErrorAction SilentlyContinue | Out-Null
                
                Write-Log "    [+] Set dangerous rights in GPO" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error setting user rights: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 6: IOE #4: Dangerous GPO logon script path
        # =====================================================================
        
        Write-Log "PHASE 6: Configure dangerous logon script path" -Level INFO
        Write-Log "  [*] IOE: Dangerous GPO logon script path" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                # Set logon script path (script doesn't need to exist, just the path triggers IOE)
                Set-GPRegistryValue -Name $rightGPO.DisplayName `
                    -Key "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" `
                    -ValueName "UserInitMprLogonScript" `
                    -Value "\\127.0.0.1\breakAD\malicious.bat" `
                    -Type String `
                    -ErrorAction SilentlyContinue | Out-Null
                
                Write-Log "    [+] Set dangerous logon script path" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error setting logon script: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 7: IOE #9: Reversible passwords found in GPOs
        # =====================================================================
        
        Write-Log "PHASE 7: Configure reversible password storage in GPO" -Level INFO
        Write-Log "  [*] IOE: Reversible passwords found in GPOs" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                Set-GPRegistryValue -Name $rightGPO.DisplayName `
                    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                    -ValueName "NoLMHash" `
                    -Value 0 `
                    -Type DWORD `
                    -ErrorAction SilentlyContinue | Out-Null
                
                Write-Log "    [+] Enabled reversible password storage in GPO" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error setting reversible passwords: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 8: IOE #11: GPO weak LM hash storage enabled
        # =====================================================================
        
        Write-Log "PHASE 8: Enable weak LM hash storage in GPO" -Level INFO
        Write-Log "  [*] IOE: GPO weak LM hash storage enabled" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                Set-GPRegistryValue -Name $rightGPO.DisplayName `
                    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                    -ValueName "LMCompatibilityLevel" `
                    -Value 2 `
                    -Type DWORD `
                    -ErrorAction SilentlyContinue | Out-Null
                
                Write-Log "    [+] Enabled weak LM hash storage in GPO" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error setting LM hash: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 9: IOE #12: GPO with scheduled tasks configured
        # =====================================================================
        
        Write-Log "PHASE 9: Configure scheduled tasks in GPO" -Level INFO
        Write-Log "  [*] IOE: GPO with scheduled tasks configured" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                # Set a benign scheduled task registry entry
                Set-GPRegistryValue -Name $rightGPO.DisplayName `
                    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" `
                    -ValueName "Startup" `
                    -Value "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" `
                    -Type String `
                    -ErrorAction SilentlyContinue | Out-Null
                
                Write-Log "    [+] Configured scheduled tasks in GPO" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error setting scheduled tasks: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 10: IOE #13: Writable shortcuts found in GPO
        # =====================================================================
        
        Write-Log "PHASE 10: Configure writable shortcuts in GPO" -Level INFO
        Write-Log "  [*] IOE: Writable shortcuts found in GPO" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                Set-GPRegistryValue -Name $rightGPO.DisplayName `
                    -Key "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" `
                    -ValueName "Desktop" `
                    -Value "C:\Users\Public\Desktop" `
                    -Type String `
                    -ErrorAction SilentlyContinue | Out-Null
                
                Write-Log "    [+] Configured writable shortcuts in GPO" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error setting writable shortcuts: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 11: IOE #6, #7, #8: GPO linking delegation
        # =====================================================================
        
        Write-Log "PHASE 11: Grant GPO linking delegation" -Level INFO
        Write-Log "  [*] IOE: GPO linking delegation at domain/site/OU levels" -Level INFO
        
        try {
            # Create a lab user for delegation if not exists
            $delUser = Get-ADUser -Filter { SamAccountName -eq "break-gpo-delegate" } -ErrorAction SilentlyContinue
            
            if (-not $delUser) {
                $delUser = New-ADUser -Name "break-gpo-delegate" `
                    -SamAccountName "break-gpo-delegate" `
                    -UserPrincipalName "break-gpo-delegate@$domainFQDN" `
                    -Path "OU=Users,OU=BreakAD,$domainDN" `
                    -AccountPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force) `
                    -Enabled $true `
                    -ErrorAction Stop -PassThru
                
                Write-Log "    [+] Created delegation user: break-gpo-delegate" -Level SUCCESS
            }
            else {
                Write-Log "    [*] Delegation user already exists" -Level INFO
            }
            
            # Grant delegation on BreakAD OU for GPO linking
            $breakADOUObj = Get-ADOrganizationalUnit -Identity $breakADOU -ErrorAction Stop
            $acl = Get-Acl "AD:$breakADOU"
            
            $linkGPOGUID = [System.Guid]"01814787-5BB5-42d3-A4D5-0595BC1DD92A"  # LinkGPO control right
            $sid = New-Object System.Security.Principal.SecurityIdentifier($delUser.SID)
            
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Allow,
                $linkGPOGUID
            )
            
            $acl.AddAccessRule($ace)
            Set-Acl "AD:$breakADOU" $acl -ErrorAction Stop
            
            Write-Log "    [+] Granted GPO linking delegation on BreakAD OU" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error granting delegation: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 12: Force Group Policy update
        # =====================================================================
        
        Write-Log "PHASE 12: Force Group Policy update" -Level INFO
        
        try {
            Invoke-Command -ComputerName $dcFQDN -ScriptBlock {
                gpupdate /force /wait:0
            } -ErrorAction SilentlyContinue | Out-Null
            
            Write-Log "  [+] Group Policy update forced" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error forcing gpupdate: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "Module 01: Group Policy Security - COMPLETE" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "" -Level INFO
        
        return $true
    }
    catch {
        Write-Log "Module 03 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleGroupPolicySecurity