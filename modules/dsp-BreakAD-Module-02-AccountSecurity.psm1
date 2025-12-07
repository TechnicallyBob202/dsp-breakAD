################################################################################
##
## dsp-BreakAD-Module-02-AccountSecurity.psm1
##
## Purpose: Introduce Account Security misconfigurations to lower DSP score
## Targets: Account Security IOE category in DSP
##
## IOEs Targeted (16):
##  1. Unprivileged accounts with adminCount=1
##  2. User accounts that store passwords with reversible encryption
##  3. User accounts that use DES encryption
##  4. User accounts with password not required
##  5. Users with Kerberos pre-authentication disabled
##  6. Recent privileged account creation activity
##  7. Privileged accounts with a password that never expires
##  8. Privileged users with weak password policy (via PSO)
##  9. Unprivileged principals as DNS Admins
## 10. Recent sIDHistory changes on objects
## 11. AD objects created within the last 10 days
## 12. Users with old passwords
## 13. Users with Password Never Expires flag set
## 14. Changes to privileged group membership
## 15. Computer accounts in privileged groups
## 16. Schema Admins group is not empty
##
## Design Philosophy:
##  - All test accounts created in BreakAD\Users OU
##  - Test computers created in BreakAD\Computers OU
##  - Group membership changes are temporary (can be reverted)
##  - Idempotent: safe to run multiple times
##
## Author: Bob (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleAccountSecurity {
    <#
    .SYNOPSIS
        Introduce Account Security misconfigurations to DSP detection range
    
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
    Write-Log "Module 02: Account Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    try {
        # Generate random suffix for test accounts
        $suffix = Get-Random -Minimum 100 -Maximum 999
        
        $breakADOUUsers = "OU=Users,OU=BreakAD,$domainDN"
        $breakADOUComputers = "OU=Computers,OU=BreakAD,$domainDN"
        
        # =====================================================================
        # PHASE 1: Create test accounts with dangerous attribute flags
        # =====================================================================
        
        Write-Log "PHASE 1: Create test accounts with dangerous attributes" -Level INFO
        
        $testAccounts = @()
        
        # IOE #2: Reversible encryption
        try {
            $acct = New-ADUser -Name "break-revenc-$suffix" `
                -SamAccountName "break-revenc-$suffix" `
                -UserPrincipalName "break-revenc-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            Set-ADUser -Identity $acct -AllowReversiblePasswordEncryption $true -ErrorAction SilentlyContinue
            Write-Log "  [+] Created account with reversible encryption: $($acct.SamAccountName)" -Level SUCCESS
            $testAccounts += $acct
        }
        catch {
            Write-Log "  [!] Error creating reversible encryption account: $_" -Level WARNING
        }
        
        # IOE #3: DES encryption
        try {
            $acct = New-ADUser -Name "break-des-$suffix" `
                -SamAccountName "break-des-$suffix" `
                -UserPrincipalName "break-des-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            Set-ADUser -Identity $acct -Replace @{"msDS-SupportedEncryptionTypes" = 1} -ErrorAction SilentlyContinue
            Write-Log "  [+] Created account with DES encryption: $($acct.SamAccountName)" -Level SUCCESS
            $testAccounts += $acct
        }
        catch {
            Write-Log "  [!] Error creating DES encryption account: $_" -Level WARNING
        }
        
        # IOE #4: Password not required
        try {
            $acct = New-ADUser -Name "break-nopwd-$suffix" `
                -SamAccountName "break-nopwd-$suffix" `
                -UserPrincipalName "break-nopwd-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -PasswordNotRequired $true `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            Write-Log "  [+] Created account with password not required: $($acct.SamAccountName)" -Level SUCCESS
            $testAccounts += $acct
        }
        catch {
            Write-Log "  [!] Error creating password-not-required account: $_" -Level WARNING
        }
        
        # IOE #5: Pre-authentication disabled
        try {
            $acct = New-ADUser -Name "break-nopreauth-$suffix" `
                -SamAccountName "break-nopreauth-$suffix" `
                -UserPrincipalName "break-nopreauth-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            Set-ADUser -Identity $acct -Replace @{"userAccountControl" = 0x1000010} -ErrorAction SilentlyContinue
            Write-Log "  [+] Created account with pre-authentication disabled: $($acct.SamAccountName)" -Level SUCCESS
            $testAccounts += $acct
        }
        catch {
            Write-Log "  [!] Error creating pre-auth disabled account: $_" -Level WARNING
        }
        
        # IOE #1: adminCount=1 on unprivileged account
        try {
            $acct = New-ADUser -Name "break-admincnt-$suffix" `
                -SamAccountName "break-admincnt-$suffix" `
                -UserPrincipalName "break-admincnt-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            Set-ADUser -Identity $acct -Replace @{"adminCount" = 1} -ErrorAction SilentlyContinue
            Write-Log "  [+] Created unprivileged account with adminCount=1: $($acct.SamAccountName)" -Level SUCCESS
            $testAccounts += $acct
        }
        catch {
            Write-Log "  [!] Error creating adminCount account: $_" -Level WARNING
        }
        

        
        # IOE #13: Password never expires
        try {
            $acct = New-ADUser -Name "break-neverexp-$suffix" `
                -SamAccountName "break-neverexp-$suffix" `
                -UserPrincipalName "break-neverexp-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -PasswordNotRequired $false `
                -ErrorAction Stop -PassThru
            
            Set-ADUser -Identity $acct -PasswordNeverExpires $true -ErrorAction SilentlyContinue
            Write-Log "  [+] Created account with password never expires: $($acct.SamAccountName)" -Level SUCCESS
            $testAccounts += $acct
        }
        catch {
            Write-Log "  [!] Error creating never-expire account: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 2: Create privileged test account (IOE #6, #7)
        # =====================================================================
        
        Write-Log "PHASE 2: Create privileged test account with dangerous settings" -Level INFO
        
        try {
            $privAcct = New-ADUser -Name "break-admin-$suffix" `
                -SamAccountName "break-admin-$suffix" `
                -UserPrincipalName "break-admin-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            # IOE #7: Password never expires on privileged account
            Set-ADUser -Identity $privAcct -PasswordNeverExpires $true -ErrorAction SilentlyContinue
            
            Write-Log "  [+] Created privileged test account: $($privAcct.SamAccountName)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating privileged account: $_" -Level WARNING
            $privAcct = $null
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 3: Group membership changes (IOE #14, #15, #16)
        # =====================================================================
        
        Write-Log "PHASE 3: Modify privileged group memberships" -Level INFO
        
        # IOE #14 & #16: Add test account to Schema Admins
        try {
            $schemaAdmins = Get-ADGroup -Identity "Schema Admins" -ErrorAction Stop
            $testUser = $testAccounts[0]
            
            Add-ADGroupMember -Identity $schemaAdmins -Members $testUser -ErrorAction SilentlyContinue
            Write-Log "  [+] Added $($testUser.SamAccountName) to Schema Admins (IOE #14, #16)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error adding to Schema Admins: $_" -Level WARNING
        }
        
        # IOE #14: Add test account to Domain Admins
        try {
            $domainAdmins = Get-ADGroup -Identity "Domain Admins" -ErrorAction Stop
            $testUser = $testAccounts[1]
            
            Add-ADGroupMember -Identity $domainAdmins -Members $testUser -ErrorAction SilentlyContinue
            Write-Log "  [+] Added $($testUser.SamAccountName) to Domain Admins (IOE #14)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error adding to Domain Admins: $_" -Level WARNING
        }
        
        # IOE #15: Create test computer and add to Domain Admins
        try {
            $compAcct = New-ADComputer -Name "break-comp-$suffix" `
                -Path $breakADOUComputers `
                -ErrorAction Stop -PassThru
            
            Add-ADGroupMember -Identity "Domain Admins" -Members $compAcct -ErrorAction SilentlyContinue
            Write-Log "  [+] Created computer and added to Domain Admins: $($compAcct.Name) (IOE #15)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating computer in privileged group: $_" -Level WARNING
        }
        
        # IOE #9: Add test account to DnsAdmins
        try {
            $dnsAdmins = Get-ADGroup -Identity "DnsAdmins" -ErrorAction SilentlyContinue
            if ($dnsAdmins) {
                $testUser = $testAccounts[2]
                Add-ADGroupMember -Identity $dnsAdmins -Members $testUser -ErrorAction SilentlyContinue
                Write-Log "  [+] Added $($testUser.SamAccountName) to DnsAdmins (IOE #9)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error adding to DnsAdmins: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 4: Modify sIDHistory (IOE #10)
        # =====================================================================
        
        Write-Log "PHASE 4: Add sIDHistory entries" -Level INFO
        
        try {
            if ($privAcct -and $testAccounts.Count -gt 0) {
                # Add a test user's SID as sIDHistory to simulate domain migration
                $testSID = $testAccounts[0].SID.Value
                
                Set-ADUser -Identity $privAcct -Replace @{"sIDHistory" = $testSID} -ErrorAction Stop
                Write-Log "  [+] Added sIDHistory entry to privileged account (IOE #10)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error modifying sIDHistory: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 5: Create PSO for weak password policy (IOE #8)
        # =====================================================================
        
        Write-Log "PHASE 5: Create Fine-Grained Password Policy" -Level INFO
        

        

        Write-Log "========================================" -Level INFO
        Write-Log "Module 02: Account Security - COMPLETE" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "" -Level INFO
        
        return $true
    }
    catch {
        Write-Log "Module 02 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity