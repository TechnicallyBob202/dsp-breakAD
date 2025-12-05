################################################################################
##
## dsp-BreakAD-Module-02-AccountSecurity.psm1
##
## Account Security Misconfigurations
##
## Module 2 creates account-level security weaknesses:
## - Creates dedicated bad user accounts with various weak properties
## - Password never expires
## - Pre-auth disabled (AS-REP roasting vector)
## - Weak Kerberos encryption (DES, RC4)
## - Unconstrained delegation enabled
## - Constrained delegation to dangerous SPNs
## - Passwords stored in descriptions
## - Service account abuse scenarios
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0 - Clean rebuild from scratch
##
################################################################################

function Invoke-ModuleAccountSecurity {
    <#
    .SYNOPSIS
        Applies account security misconfigurations
    
    .PARAMETER Environment
        Hashtable containing Domain, DomainController, and Config info
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 02: Account Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 0: GET OU PATHS (from Module 1 config)
    ################################################################################
    
    Write-Log "PHASE 0: Get Organizational Unit Paths" -Level INFO
    
    $domainDN = $domain.DistinguishedName
    $rootOUName = $config['BreakAD_RootOU']
    $usersOUName = $config['BreakAD_UsersOU']
    
    $usersOUPath = "OU=$usersOUName,OU=$rootOUName,$domainDN"
    
    Write-Log "  Users OU: $usersOUPath" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 1: VALIDATE CONFIG & SETUP
    ################################################################################
    
    Write-Log "PHASE 1: Validate Config & Setup" -Level INFO
    
    $badUsersCount = [int]$config['AccountSecurity_BadUsersToCreate']
    
    Write-Log "  Bad users to create: $badUsersCount" -Level INFO
    Write-Log "  Password never expires: $($config['AccountSecurity_IncludeNeverExpiringPasswords'])" -Level INFO
    Write-Log "  Pre-auth disabled: $($config['AccountSecurity_IncludePreAuthDisabled'])" -Level INFO
    Write-Log "  Weak encryption: $($config['AccountSecurity_IncludeWeakEncryption'])" -Level INFO
    Write-Log "  Unconstrained delegation: $($config['AccountSecurity_IncludeUnconstrainedDelegation'])" -Level INFO
    Write-Log "  Constrained delegation: $($config['AccountSecurity_IncludeConstrainedDelegation'])" -Level INFO
    Write-Log "  Weak password storage: $($config['AccountSecurity_IncludeWeakPasswordStorage'])" -Level INFO
    Write-Log "  Service account abuse: $($config['AccountSecurity_IncludeServiceAccountAbuse'])" -Level INFO
    
    if ($badUsersCount -eq 0) {
        Write-Log "[*] Bad users count is 0, skipping module" -Level INFO
        return $true
    }
    
    Write-Log "[+] Config validated" -Level SUCCESS
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 2: CREATE BAD USERS WITH WEAK PROPERTIES
    ################################################################################
    
    Write-Log "PHASE 2: Create Bad Users with Weak Properties" -Level INFO
    
    $badUsers = @()
    
    for ($i = 1; $i -le $badUsersCount; $i++) {
        $userName = "break-BadUser-" + "{0:D2}" -f $i
        $userPassword = "BadP@ss!" + $i
        $userSecurePassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
        
        Write-Log "  Processing: $userName" -Level INFO
        
        # Check if user already exists
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction SilentlyContinue
        
        if ($null -ne $existingUser) {
            Write-Log "    [+] User already exists" -Level SUCCESS
            $badUsers += $existingUser
        }
        else {
            Write-Log "    Creating..." -Level INFO
            
            # Create the user
            New-ADUser `
                -Name $userName `
                -SamAccountName $userName `
                -AccountPassword $userSecurePassword `
                -Enabled $true `
                -Description "Bad Actor Account - Account Security Testing" `
                -ChangePasswordAtLogon $false `
                -Path $usersOUPath `
                -ErrorAction Stop
            
            Write-LogChange -Object $userName -Attribute "Creation" -OldValue "N/A" -NewValue "Created"
            Write-Log "    [+] Created" -Level SUCCESS
            
            # Wait for AD to process
            Start-Sleep -Seconds 2
            
            # Retrieve the user
            $newUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction Stop
            if ($null -eq $newUser) {
                Write-Log "    [!] ERROR: Could not retrieve user after creation" -Level ERROR
                return $false
            }
            
            $badUsers += $newUser
            Write-Log "    [+] Retrieved" -Level SUCCESS
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 3: APPLY WEAK PROPERTIES TO USERS
    ################################################################################
    
    Write-Log "PHASE 3: Apply Weak Properties to Users" -Level INFO
    
    for ($i = 0; $i -lt $badUsers.Count; $i++) {
        $user = $badUsers[$i]
        $userIndex = $i + 1
        
        Write-Log "  Configuring: $($user.Name)" -Level INFO
        
        ################################################################
        # PASSWORD NEVER EXPIRES
        ################################################################
        
        if ($config['AccountSecurity_IncludeNeverExpiringPasswords'] -eq 'true') {
            try {
                Set-ADUser -Identity $user -PasswordNeverExpires $true -ErrorAction Stop
                Write-LogChange -Object $user.Name -Attribute "PasswordNeverExpires" -OldValue "False" -NewValue "True"
                Write-Log "    [+] Password never expires enabled" -Level SUCCESS
            }
            catch {
                Write-Log "    [!] Error setting password never expires: $_" -Level ERROR
                return $false
            }
        }
        
        ################################################################
        # PRE-AUTH DISABLED (AS-REP ROASTING)
        ################################################################
        
        if ($config['AccountSecurity_IncludePreAuthDisabled'] -eq 'true') {
            try {
                Set-ADUser -Identity $user -DoesNotRequirePreAuth $true -ErrorAction Stop
                Write-LogChange -Object $user.Name -Attribute "DoesNotRequirePreAuth" -OldValue "False" -NewValue "True"
                Write-Log "    [+] Pre-auth disabled (AS-REP roasting vector)" -Level SUCCESS
            }
            catch {
                Write-Log "    [!] Error disabling pre-auth: $_" -Level ERROR
                return $false
            }
        }
        
        ################################################################
        # WEAK KERBEROS ENCRYPTION
        ################################################################
        
        if ($config['AccountSecurity_IncludeWeakEncryption'] -eq 'true') {
            try {
                if ($userIndex -eq 1) {
                    # DES only
                    Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 1} -ErrorAction Stop
                    Write-LogChange -Object $user.Name -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "DES Only (1)"
                    Write-Log "    [+] Encryption: DES only" -Level SUCCESS
                }
                elseif ($userIndex -eq 2) {
                    # RC4 only
                    Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 4} -ErrorAction Stop
                    Write-LogChange -Object $user.Name -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "RC4 Only (4)"
                    Write-Log "    [+] Encryption: RC4 only" -Level SUCCESS
                }
                elseif ($userIndex -eq 3) {
                    # DES + RC4
                    Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 5} -ErrorAction Stop
                    Write-LogChange -Object $user.Name -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "DES + RC4 (5)"
                    Write-Log "    [+] Encryption: DES + RC4" -Level SUCCESS
                }
            }
            catch {
                Write-Log "    [!] Error setting weak encryption: $_" -Level ERROR
                return $false
            }
        }
        
        ################################################################
        # UNCONSTRAINED DELEGATION
        ################################################################
        
        if ($config['AccountSecurity_IncludeUnconstrainedDelegation'] -eq 'true' -and $userIndex -le 2) {
            try {
                Set-ADUser -Identity $user -TrustedForDelegation $true -ErrorAction Stop
                Write-LogChange -Object $user.Name -Attribute "TrustedForDelegation" -OldValue "False" -NewValue "True"
                Write-Log "    [+] Unconstrained delegation enabled" -Level SUCCESS
            }
            catch {
                Write-Log "    [!] Error enabling unconstrained delegation: $_" -Level ERROR
                return $false
            }
        }
        
        ################################################################
        # CONSTRAINED DELEGATION TO DANGEROUS SPNS
        ################################################################
        
        if ($config['AccountSecurity_IncludeConstrainedDelegation'] -eq 'true' -and $userIndex -eq 3) {
            try {
                $spns = @(
                    "ldap/$($domain.DNSRoot)",
                    "cifs/$($domain.DNSRoot)",
                    "host/$($domain.DNSRoot)"
                )
                
                Set-ADUser -Identity $user -Replace @{"msDS-AllowedToDelegateTo" = $spns} -ErrorAction Stop
                Write-LogChange -Object $user.Name -Attribute "msDS-AllowedToDelegateTo" -OldValue "None" -NewValue "LDAP, CIFS, Host"
                Write-Log "    [+] Constrained delegation to dangerous SPNs" -Level SUCCESS
            }
            catch {
                Write-Log "    [!] Error setting constrained delegation: $_" -Level ERROR
                return $false
            }
        }
        
        ################################################################
        # WEAK PASSWORD STORAGE (IN DESCRIPTION)
        ################################################################
        
        if ($config['AccountSecurity_IncludeWeakPasswordStorage'] -eq 'true' -and $userIndex -eq 4) {
            try {
                Set-ADUser -Identity $user -Description "Password: WeakPass123!" -ErrorAction Stop
                Write-LogChange -Object $user.Name -Attribute "Description" -OldValue "Default" -NewValue "Contains password"
                Write-Log "    [+] Weak password stored in description" -Level SUCCESS
            }
            catch {
                Write-Log "    [!] Error storing password in description: $_" -Level ERROR
                return $false
            }
        }
        
        ################################################################
        # SERVICE ACCOUNT ABUSE
        ################################################################
        
        if ($config['AccountSecurity_IncludeServiceAccountAbuse'] -eq 'true' -and $userIndex -eq 5) {
            try {
                Set-ADUser -Identity $user -PasswordNeverExpires $true -ErrorAction Stop
                Set-ADUser -Identity $user -Description "Shared service account - weak configuration" -ErrorAction Stop
                Write-LogChange -Object $user.Name -Attribute "ServiceAccountAbuse" -OldValue "No" -NewValue "Yes"
                Write-Log "    [+] Service account abuse configured" -Level SUCCESS
            }
            catch {
                Write-Log "    [!] Error configuring service account abuse: $_" -Level ERROR
                return $false
            }
        }
        
        Write-Log "" -Level INFO
    }
    
    ################################################################################
    # COMPLETION
    ################################################################################
    
    Write-Log "========================================" -Level INFO
    Write-Log "Module 02: Account Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Status: COMPLETE" -Level SUCCESS
    Write-Log "Users created/configured: $($badUsers.Count)" -Level SUCCESS
    Write-Log "" -Level INFO
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity