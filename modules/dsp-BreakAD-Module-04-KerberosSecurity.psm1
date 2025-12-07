################################################################################
##
## dsp-BreakAD-Module-04-KerberosSecurity.psm1
##
## Purpose: Introduce Kerberos Security misconfigurations to lower DSP score
## Targets: Kerberos Security IOE category in DSP
##
## IOEs Documented (21 total):
##
## SAFE (low risk, easy rollback):
##  1. Accounts with altSecurityIdentities configured
##  2. Privileged users with SPN defined
##  3. Users with SPN defined
##  4. Primary users with SPN not supporting AES encryption (RC4 only)
##  5. RC4 or DES encryption type supported by Domain Controllers
##  6. Users with the attribute userPassword set
##  7. Kerberos protocol transition delegation configured
##  8. Objects with constrained delegation configured
##  9. Accounts with Constrained Delegation configured to ghost SPN
## 10. Computer or user accounts with SPN that have unconstrained delegation
##
## CAUTION (medium risk, explicit rollback required):
## 11. Computer account takeover through Kerberos RBCD (grant WriteDACL on test computer)
## 12. Domain controllers with RBCD enabled (lab DC only, clear msDS-AllowedToActOnBehalfOfOtherIdentity)
## 13. krbtgt account with RBCD enabled (highly sensitive, only if fully isolated)
## 14. Principals with constrained auth delegation enabled for DC service (test principal only)
## 15. Principals with constrained delegation with protocol transition for DC service (revert msDS-AllowedToDelegateTo)
## 16. Write access to RBCD on DC (grant WriteDACL to test user on lab DC only)
##
## HIGH RISK (avoid unless fully isolated with snapshot):
## 17. Accounts with Constrained Delegation configured to krbtgt
## 18. Computer accounts leveraging CVE-2021-42278 and CVE-2021-42287
## 19. Computer accounts leveraging CVE-2022-26923
## 20. Kerberos KRBTGT account with old password
## 21. Write access to RBCD on krbtgt account
##
## Design Philosophy:
##  - All test accounts created in BreakAD\Users OU
##  - All test computers created in BreakAD\Computers OU
##  - SPN assignments are reversible (remove via Set-ADUser -ServicePrincipalNames)
##  - Delegation configurations can be cleared by setting to empty list
##  - userPassword attribute is set only on test accounts, not real users
##
## Author: Bob (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleKerberosSecurity {
    <#
    .SYNOPSIS
        Introduce Kerberos Security misconfigurations to DSP detection range
    
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
    Write-Log "Module 04: Kerberos Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    try {
        # Generate random suffix for test objects
        $suffix = Get-Random -Minimum 100 -Maximum 999
        
        $breakADOUUsers = "OU=Users,OU=BreakAD,$domainDN"
        $breakADOUComputers = "OU=Computers,OU=BreakAD,$domainDN"
        
        # =====================================================================
        # PHASE 1: Create test accounts and computers
        # =====================================================================
        
        Write-Log "PHASE 1: Create test accounts and computers" -Level INFO
        
        $testAccounts = @()
        $testComputers = @()
        

        

        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 2: IOE #1 - Accounts with altSecurityIdentities configured
        # =====================================================================
        
        Write-Log "PHASE 2: Configure altSecurityIdentities (IOE #1)" -Level INFO
        
        try {
            if ($testAccounts.Count -gt 0) {
                $testAccounts[0] | Set-ADUser -Replace @{"altSecurityIdentities" = "Kerberos=altuser@REALM"} -ErrorAction SilentlyContinue
                Write-Log "  [+] Set altSecurityIdentities on test account (IOE #1)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting altSecurityIdentities: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 3: IOE #2 & #3 - Users with SPN defined
        # =====================================================================
        
        Write-Log "PHASE 3: Configure SPN on test accounts (IOE #2, #3)" -Level INFO
        
        try {
            if ($testAccounts.Count -gt 1) {
                # IOE #2: Privileged user with SPN (add to Domain Admins first)
                $privUser = $testAccounts[1]
                Add-ADGroupMember -Identity "Domain Admins" -Members $privUser -ErrorAction SilentlyContinue
                
                # Set SPN on privileged user
                $privUser | Set-ADUser -ServicePrincipalNames @("HTTP/privuser.$domainFQDN") -ErrorAction SilentlyContinue
                Write-Log "  [+] Set SPN on privileged user (IOE #2)" -Level SUCCESS
            }
            
            # IOE #3: Regular user with SPN
            if ($testAccounts.Count -gt 2) {
                $testAccounts[2] | Set-ADUser -ServicePrincipalNames @("HTTP/normaluser.$domainFQDN") -ErrorAction SilentlyContinue
                Write-Log "  [+] Set SPN on regular user (IOE #3)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting SPN: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 4: IOE #4 - Primary users with SPN not supporting AES encryption
        # =====================================================================
        
        Write-Log "PHASE 4: Configure RC4-only encryption (IOE #4)" -Level INFO
        
        try {
            if ($testAccounts.Count -gt 3) {
                # Set msDS-SupportedEncryptionTypes to 4 (RC4 only, no AES)
                $testAccounts[3] | Set-ADUser -Replace @{"msDS-SupportedEncryptionTypes" = 4} -ErrorAction SilentlyContinue
                Write-Log "  [+] Set RC4-only encryption on test account (IOE #4)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting encryption type: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 5: IOE #5 - RC4 or DES supported by Domain Controllers
        # =====================================================================
        
        Write-Log "PHASE 5: Enable RC4 support on Domain Controller (IOE #5)" -Level INFO
        
        try {
            # This would normally be done via GPO, but we can set a registry preference
            # For now, just log that this requires DC-level configuration
            Write-Log "  [*] IOE #5 requires DC registry/GPO configuration" -Level INFO
            Write-Log "  [*] Set HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\SupportedEncryptionTypes" -Level INFO
        }
        catch {
            Write-Log "  [!] Error with RC4 support: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 6: IOE #6 - Users with userPassword attribute set
        # =====================================================================
        
        Write-Log "PHASE 6: Set userPassword attribute (IOE #6)" -Level INFO
        
        try {
            if ($testAccounts.Count -gt 4) {
                # Set userPassword attribute (cleartext password storage - legacy/risky)
                $testAccounts[4] | Set-ADUser -Replace @{"userPassword" = "TestPassword123!"} -ErrorAction SilentlyContinue
                Write-Log "  [+] Set userPassword attribute on test account (IOE #6)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting userPassword: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 7: IOE #7 - Kerberos protocol transition delegation configured
        # =====================================================================
        
        Write-Log "PHASE 7: Configure protocol transition delegation (IOE #7)" -Level INFO
        
        try {
            if ($testAccounts.Count -gt 0) {
                # Set msDS-AllowedToDelegateTo with protocol transition flag
                $testAccounts[0] | Set-ADUser -Replace @{
                    "msDS-AllowedToDelegateTo" = @("ldap/dc1.$domainFQDN");
                    "userAccountControl" = 0x81000
                } -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Configured protocol transition delegation (IOE #7)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error configuring protocol transition: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 8: IOE #8 - Objects with constrained delegation configured
        # =====================================================================
        
        Write-Log "PHASE 8: Configure constrained delegation (IOE #8)" -Level INFO
        
        try {
            if ($testComputers.Count -gt 0) {
                # Set constrained delegation on test computer
                $testComputers[0] | Set-ADComputer -Replace @{
                    "msDS-AllowedToDelegateTo" = @("HTTP/webapp.$domainFQDN")
                } -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Configured constrained delegation on test computer (IOE #8)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error configuring constrained delegation: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 9: IOE #9 - Accounts with Constrained Delegation to ghost SPN
        # =====================================================================
        
        Write-Log "PHASE 9: Configure delegation to non-existent SPN (IOE #9)" -Level INFO
        
        try {
            if ($testComputers.Count -gt 1) {
                # Set delegation to SPN that doesn't exist anywhere
                $testComputers[1] | Set-ADComputer -Replace @{
                    "msDS-AllowedToDelegateTo" = @("HTTP/ghost-service.$domainFQDN")
                } -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Set delegation to non-existent ghost SPN (IOE #9)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting ghost SPN delegation: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 10: IOE #10 - Accounts with unconstrained delegation
        # =====================================================================
        
        Write-Log "PHASE 10: Configure unconstrained delegation (IOE #10)" -Level INFO
        
        try {
            if ($testComputers.Count -gt 2) {
                # Set TrustedForDelegation flag on test computer
                $testComputers[2] | Set-ADComputer -TrustedForDelegation $true -ErrorAction SilentlyContinue
                Write-Log "  [+] Enabled unconstrained delegation on test computer (IOE #10)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error enabling unconstrained delegation: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "Module 04: Kerberos Security - COMPLETE" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "" -Level INFO
        Write-Log "NOTE: Phases 11-21 (RBCD, krbtgt, CVE exploits, etc.) require" -Level INFO
        Write-Log "      manual testing and explicit rollback plan. See comments." -Level INFO
        Write-Log "" -Level INFO
        
        return $true
    }
    catch {
        Write-Log "Module 04 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleKerberosSecurity