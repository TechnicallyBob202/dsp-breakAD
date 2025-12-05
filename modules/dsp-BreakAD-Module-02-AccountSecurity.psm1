################################################################################
##
## dsp-BreakAD-Module-02-AccountSecurity.psm1
##
## Configures account security misconfigurations
## - Creates user accounts with weak security settings
## - Password never expires
## - Pre-auth disabled (AS-REP roasting)
## - Weak Kerberos encryption (DES, RC4)
## - Unconstrained delegation
## - Constrained delegation to dangerous SPNs
## - Service account abuse scenarios
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleAccountSecurity {
    <#
    .SYNOPSIS
        Applies account security misconfigurations
    
    .PARAMETER Environment
        Hashtable containing Domain and DomainController info
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    $successCount = 0
    $errorCount = 0
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    
    Write-Log "Account Security Module Starting" -Level INFO
    Write-Log "Domain: $($domain.Name)" -Level INFO
    Write-Log "" -Level INFO
    
    $badUsersCount = [int]$config['AccountSecurity_BadUsersToCreate']
    if ($badUsersCount -eq 0) {
        Write-Log "No bad users configured to create" -Level INFO
        return $true
    }
    
    Write-Log "Creating $badUsersCount bad user account(s)..." -Level INFO
    Write-Log "" -Level INFO
    
    for ($i = 1; $i -le $badUsersCount; $i++) {
        $userName = "break-User-$i"
        $userEmail = "break-user-$i@$domainFQDN"
        $password = ConvertTo-SecureString "BadP@ss!$i" -AsPlainText -Force
        
        Write-Log "Creating user: $userName" -Level INFO
        
        try {
            # Check if user exists
            $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
            if ($existingUser) {
                Write-Log "  [*] User already exists, updating properties..." -Level INFO
            }
            else {
                New-ADUser -Name $userName `
                    -SamAccountName $userName `
                    -AccountPassword $password `
                    -Enabled $true `
                    -EmailAddress $userEmail `
                    -ErrorAction Stop
                
                Write-Log "  [+] User created: $userName" -Level SUCCESS
            }
            
            $user = Get-ADUser -Identity $userName -ErrorAction Stop
            
            ################################################################
            # PASSWORD NEVER EXPIRES
            ################################################################
            
            if ($config['AccountSecurity_IncludeNeverExpiringPasswords'] -eq 'true') {
                try {
                    Set-ADUser -Identity $user -PasswordNeverExpires $true -ErrorAction Stop
                    Write-LogChange -Object $userName -Attribute "PasswordNeverExpires" -OldValue "False" -NewValue "True"
                    Write-Log "  [+] Password set to never expire" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error setting password never expires: $_" -Level WARNING
                    $errorCount++
                }
            }
            
            ################################################################
            # PRE-AUTH DISABLED (AS-REP ROASTING)
            ################################################################
            
            if ($config['AccountSecurity_IncludePreAuthDisabled'] -eq 'true' -and $i -le 2) {
                try {
                    Set-ADUser -Identity $user -DoesNotRequirePreAuth $true -ErrorAction Stop
                    Write-LogChange -Object $userName -Attribute "DoesNotRequirePreAuth" -OldValue "False" -NewValue "True"
                    Write-Log "  [+] Pre-auth disabled (AS-REP roasting vector)" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error disabling pre-auth: $_" -Level WARNING
                    $errorCount++
                }
            }
            
            ################################################################
            # WEAK KERBEROS ENCRYPTION
            ################################################################
            
            if ($config['AccountSecurity_IncludeWeakEncryption'] -eq 'true') {
                try {
                    if ($i -eq 1) {
                        # DES only
                        Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 1} -ErrorAction Stop
                        Write-LogChange -Object $userName -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "DES Only (1)"
                        Write-Log "  [+] Weak encryption set: DES only" -Level SUCCESS
                    }
                    elseif ($i -eq 2) {
                        # RC4 only
                        Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 4} -ErrorAction Stop
                        Write-LogChange -Object $userName -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "RC4 Only (4)"
                        Write-Log "  [+] Weak encryption set: RC4 only" -Level SUCCESS
                    }
                    elseif ($i -eq 3) {
                        # DES + RC4
                        Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 5} -ErrorAction Stop
                        Write-LogChange -Object $userName -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "DES + RC4 (5)"
                        Write-Log "  [+] Weak encryption set: DES + RC4" -Level SUCCESS
                    }
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error setting weak encryption: $_" -Level WARNING
                    $errorCount++
                }
            }
            
            ################################################################
            # UNCONSTRAINED DELEGATION
            ################################################################
            
            if ($config['AccountSecurity_IncludeUnconstrainedDelegation'] -eq 'true' -and $i -le 2) {
                try {
                    Set-ADUser -Identity $user -TrustedForDelegation $true -ErrorAction Stop
                    Write-LogChange -Object $userName -Attribute "TrustedForDelegation" -OldValue "False" -NewValue "True"
                    Write-Log "  [+] Unconstrained delegation enabled" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error enabling unconstrained delegation: $_" -Level WARNING
                    $errorCount++
                }
            }
            
            ################################################################
            # CONSTRAINED DELEGATION TO DANGEROUS SPNs
            ################################################################
            
            if ($config['AccountSecurity_IncludeConstrainedDelegation'] -eq 'true' -and $i -eq 3) {
                try {
                    # Grant S4U2Self + S4U2Proxy to dangerous services
                    $spns = @(
                        "ldap/dc.corp.local",
                        "cifs/dc.corp.local",
                        "host/dc.corp.local"
                    )
                    
                    Set-ADUser -Identity $user -ServicePrincipalNames @{Add = $spns} -ErrorAction Stop
                    Set-ADUser -Identity $user -Replace @{"msDS-AllowedToDelegateTo" = $spns} -ErrorAction Stop
                    
                    Write-LogChange -Object $userName -Attribute "msDS-AllowedToDelegateTo" -OldValue "None" -NewValue "LDAP, CIFS, Host on DC"
                    Write-Log "  [+] Constrained delegation configured to dangerous SPNs" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error configuring constrained delegation: $_" -Level WARNING
                    $errorCount++
                }
            }
            
            ################################################################
            # WEAK PASSWORD STORAGE (in description)
            ################################################################
            
            if ($config['AccountSecurity_IncludeWeakPasswordStorage'] -eq 'true' -and $i -eq 4) {
                try {
                    Set-ADUser -Identity $user -Description "Password: TempPassword123!" -ErrorAction Stop
                    Write-LogChange -Object $userName -Attribute "Description" -OldValue "Empty" -NewValue "Contains password"
                    Write-Log "  [+] Weak password stored in description" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error setting description: $_" -Level WARNING
                    $errorCount++
                }
            }
            
            ################################################################
            # SERVICE ACCOUNT ABUSE
            ################################################################
            
            if ($config['AccountSecurity_IncludeServiceAccountAbuse'] -eq 'true' -and $i -eq 5) {
                try {
                    # Create service account with shared password and no pre-auth
                    Set-ADUser -Identity $user -DoesNotRequirePreAuth $true -ErrorAction Stop
                    Set-ADUser -Identity $user -PasswordNeverExpires $true -ErrorAction Stop
                    Set-ADUser -Identity $user -Description "Shared service account - DO NOT CHANGE" -ErrorAction Stop
                    
                    Write-LogChange -Object $userName -Attribute "ServiceAccount" -OldValue "No" -NewValue "Yes"
                    Write-Log "  [+] Service account abuse configured" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error configuring service account: $_" -Level WARNING
                    $errorCount++
                }
            }
            
            Write-Log "" -Level INFO
        }
        catch {
            Write-Log "  [!] Error creating user $userName : $_" -Level WARNING
            $errorCount++
        }
    }
    
    ################################################################################
    # SUMMARY
    ################################################################################
    
    Write-Log "Account Security Module Complete" -Level INFO
    Write-Log "Successful changes: $successCount" -Level SUCCESS
    if ($errorCount -gt 0) {
        Write-Log "Errors encountered: $errorCount" -Level WARNING
        return $false
    }
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity