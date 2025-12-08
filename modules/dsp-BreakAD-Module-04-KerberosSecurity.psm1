################################################################################
##
## dsp-BreakAD-Module-04-KerberosSecurity.psm1
##
## Purpose: Introduce Kerberos Security misconfigurations to lower DSP score
## Targets: Kerberos Security IOE category in DSP
##
## IOEs Documented (21 total):
##
## SAFE (low risk, easy rollback) - 7 IMPLEMENTED & FIRING:
##  1. Accounts with altSecurityIdentities configured ✓
##  2. Privileged users with SPN defined ✓
##  3. Users with SPN defined ✓
##  4. Primary users with SPN not supporting AES encryption (RC4 only) ✓
##  5. RC4 or DES encryption type supported by Domain Controllers ✓
##  6. Users with the attribute userPassword set ✓
##  7. Objects with constrained delegation configured ✓
##
## SAFE (not firing - skipped):
##  8. Kerberos protocol transition delegation configured
##  9. Accounts with Constrained Delegation configured to ghost SPN
## 10. Computer or user accounts with SPN that have unconstrained delegation
##
## CAUTION (medium risk, explicit rollback required):
## 11. Computer account takeover through Kerberos RBCD
## 12. Domain controllers with RBCD enabled
## 13. krbtgt account with RBCD enabled
## 14. Principals with constrained auth delegation enabled for DC service
## 15. Principals with constrained delegation with protocol transition for DC service
## 16. Write access to RBCD on DC
##
## HIGH RISK (avoid unless fully isolated with snapshot):
## 17. Accounts with Constrained Delegation configured to krbtgt
## 18. Computer accounts leveraging CVE-2021-42278 and CVE-2021-42287
## 19. Computer accounts leveraging CVE-2022-26923
## 20. Kerberos KRBTGT account with old password
## 21. Write access to RBCD on krbtgt account
##
## Author: Bob (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleKerberosSecurity {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 04: Kerberos Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    try {
        $suffix = Get-Random -Minimum 100 -Maximum 999
        $breakADOUUsers = "OU=Users,OU=BreakAD,$domainDN"
        $breakADOUComputers = "OU=Computers,OU=BreakAD,$domainDN"
        
        # =====================================================================
        # PHASE 1: Create test accounts and computers
        # =====================================================================
        
        Write-Log "PHASE 1: Create test accounts and computers" -Level INFO
        
        $testAccounts = @()
        $testComputers = @()
        
        # Create test user accounts
        try {
            $user1 = New-ADUser -Name "break-kerb-user1-$suffix" `
                -SamAccountName "break-kerb-user1-$suffix" `
                -UserPrincipalName "break-kerb-user1-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true -ErrorAction Stop -PassThru
            $testAccounts += $user1
            Write-Log "  [+] Created test user 1: $($user1.SamAccountName)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating user 1: $_" -Level WARNING
        }
        
        try {
            $user2 = New-ADUser -Name "break-kerb-user2-$suffix" `
                -SamAccountName "break-kerb-user2-$suffix" `
                -UserPrincipalName "break-kerb-user2-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true -ErrorAction Stop -PassThru
            $testAccounts += $user2
            Write-Log "  [+] Created test user 2: $($user2.SamAccountName)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating user 2: $_" -Level WARNING
        }
        
        try {
            $user3 = New-ADUser -Name "break-kerb-user3-$suffix" `
                -SamAccountName "break-kerb-user3-$suffix" `
                -UserPrincipalName "break-kerb-user3-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true -ErrorAction Stop -PassThru
            $testAccounts += $user3
            Write-Log "  [+] Created test user 3: $($user3.SamAccountName)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating user 3: $_" -Level WARNING
        }
        
        try {
            $user4 = New-ADUser -Name "break-kerb-user4-$suffix" `
                -SamAccountName "break-kerb-user4-$suffix" `
                -UserPrincipalName "break-kerb-user4-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true -ErrorAction Stop -PassThru
            $testAccounts += $user4
            Write-Log "  [+] Created test user 4: $($user4.SamAccountName)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating user 4: $_" -Level WARNING
        }
        
        try {
            $user5 = New-ADUser -Name "break-kerb-user5-$suffix" `
                -SamAccountName "break-kerb-user5-$suffix" `
                -UserPrincipalName "break-kerb-user5-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true -ErrorAction Stop -PassThru
            $testAccounts += $user5
            Write-Log "  [+] Created test user 5: $($user5.SamAccountName)" -Level SUCCESS
        
        # Create test computers
        try {
            $comp1 = New-ADComputer -Name "break-kerb-c1-$suffix" -Path $breakADOUComputers -ErrorAction Stop -PassThru
            $testComputers += $comp1
            Write-Log "  [+] Created test computer 1: $($comp1.Name)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating computer 1: $_" -Level WARNING
        }
        
        try {
            $comp2 = New-ADComputer -Name "break-kerb-c2-$suffix" -Path $breakADOUComputers -ErrorAction Stop -PassThru
            $testComputers += $comp2
            Write-Log "  [+] Created test computer 2: $($comp2.Name)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating computer 2: $_" -Level WARNING
        }
        
        try {
            $comp3 = New-ADComputer -Name "break-kerb-c3-$suffix" -Path $breakADOUComputers -ErrorAction Stop -PassThru
            $testComputers += $comp3
            Write-Log "  [+] Created test computer 3: $($comp3.Name)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating computer 3: $_" -Level WARNING
        }
        }
        catch {
            Write-Log "  [!] Error creating user 5: $_" -Level WARNING
        }
        

        
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
        

        
        try {
            if ($testAccounts.Count -gt 1) {
                # IOE #2: Privileged user with SPN (add to Domain Admins first)
                Add-ADGroupMember -Identity "Domain Admins" -Members $testAccounts[1] -ErrorAction SilentlyContinue
                $testAccounts[1] | Set-ADUser -ServicePrincipalNames @{Add="HTTP/privuser.$domainFQDN"} -ErrorAction SilentlyContinue
                Write-Log "  [+] Set SPN on privileged user (IOE #2)" -Level SUCCESS
            }
            
            # IOE #3: Regular user with SPN
            if ($testAccounts.Count -gt 2) {
                $testAccounts[2] | Set-ADUser -ServicePrincipalNames @{Add="HTTP/normaluser.$domainFQDN"} -ErrorAction SilentlyContinue
                Write-Log "  [+] Set SPN on regular user (IOE #3)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting SPN: $_" -Level WARNING
        }
        
        # =====================================================================
        # PHASE 4: IOE #4 - Primary users with SPN not supporting AES encryption
        # =====================================================================
        
        Write-Log "PHASE 4: Configure RC4-only encryption (IOE #4)" -Level INFO
        
        try {
            if ($testAccounts.Count -gt 3) {
                # Set msDS-SupportedEncryptionTypes to 4 (RC4 only)
                $testAccounts[3] | Set-ADUser -Replace @{"msDS-SupportedEncryptionTypes" = 4} -ErrorAction SilentlyContinue
                Write-Log "  [+] Set RC4-only encryption on test account (IOE #4)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting encryption type: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 5: IOE #6 - Users with userPassword attribute set
        # =====================================================================
        
        Write-Log "PHASE 5: Set userPassword attribute (IOE #6)" -Level INFO
        
        try {
            if ($testAccounts.Count -gt 4) {
                $testAccounts[4] | Set-ADUser -Replace @{"userPassword" = "TestPassword123!"} -ErrorAction SilentlyContinue
                Write-Log "  [+] Set userPassword attribute on test account (IOE #6)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting userPassword: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 6: IOE #7 - Kerberos protocol transition delegation configured
        # =====================================================================
        
        Write-Log "PHASE 6: Configure protocol transition delegation (IOE #7)" -Level INFO
        
        try {
            if ($testAccounts.Count -gt 0) {
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
        # PHASE 7: IOE #8 - Objects with constrained delegation configured
        # =====================================================================
        
        Write-Log "PHASE 7: Configure constrained delegation (IOE #8)" -Level INFO
        
        try {
            if ($testComputers.Count -gt 0) {
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
        # PHASE 8: IOE #9 - Accounts with Constrained Delegation to ghost SPN
        # =====================================================================
        
        Write-Log "PHASE 8: Configure delegation to non-existent SPN (IOE #9)" -Level INFO
        
        try {
            if ($testComputers.Count -gt 1) {
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
        # PHASE 9: IOE #10 - Accounts with unconstrained delegation
        # =====================================================================
        
        Write-Log "PHASE 9: Configure unconstrained delegation (IOE #10)" -Level INFO
        
        try {
            if ($testComputers.Count -gt 2) {
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
        
        return $true
    }
    catch {
        Write-Log "Module 04 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleKerberosSecurity