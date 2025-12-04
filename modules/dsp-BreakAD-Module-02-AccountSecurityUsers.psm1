################################################################################
##
## dsp-BreakAD-Module-02-AccountSecurityUsers.psm1
##
## Creates user accounts with various bad security configurations
## 
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Invoke-AccountSecurityUsers {
    <#
    .SYNOPSIS
        Creates user accounts with bad security configurations
    
    .DESCRIPTION
        Creates individual user accounts with security misconfigurations:
        - Password never expires
        - Sensitive and not delegatable
        - Does not require pre-auth
        - Use DES keys only
        - Password not required
        - Kerberos encryption variations (DES, RC4, AES128, AES256, combinations)
        - Service principal names
        - Unconstrained delegation
        - Constrained delegation (with/without services)
        - Resource-based delegation
        - SID History
        - LM hashes
        - Reversible encryption
        - Compromised password
        - Smartcard required
    
    .PARAMETER Environment
        Hashtable containing domain information from preflight checks
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    $pdcFsmoFQDN = $domain.PDCEmulator
    $rwdcFQDN = $Environment.DomainController.HostName
    
    # Ensure TEST OU exists
    $testOU = "OU=TEST,$domainDN"
    if (-not (Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $testOU } -ErrorAction SilentlyContinue)) {
        Write-Host "Creating TEST OU..." -ForegroundColor Cyan
        New-ADOrganizationalUnit -Name "TEST" -Path $domainDN -ErrorAction SilentlyContinue
    }
    
    Write-Host "Creating user accounts with bad security configurations..." -ForegroundColor Cyan
    Write-Host ""
    
    $successCount = 0
    $skipCount = 0
    
    # Helper function to create a user with specific configurations
    function New-BadUser {
        param(
            [string]$Description,
            [hashtable]$AccountControl = @{},
            [hashtable]$AdditionalParams = @{}
        )
        
        $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
        $samAccountName = "USER$randomNr"
        
        # Check if already exists
        if (Get-ADUser -Filter { SamAccountName -eq $samAccountName } -ErrorAction SilentlyContinue) {
            Write-Host "  Skipping (exists): $Description" -ForegroundColor Yellow
            return $false
        }
        
        try {
            $password = $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
            
            # Create user
            $newUserParams = @{
                Path = $testOU
                Enabled = $true
                Name = "USER$randomNr"
                GivenName = "USER"
                Surname = $randomNr
                DisplayName = "USER$randomNr"
                SamAccountName = $samAccountName
                UserPrincipalName = "USER.$randomNr@$domainFQDN"
                AccountPassword = (ConvertTo-SecureString $password -AsPlainText -Force)
                Server = $rwdcFQDN
                ErrorAction = 'Stop'
            }
            
            New-ADUser @newUserParams
            
            # Set additional attributes
            $setUserParams = @{
                Identity = $samAccountName
                Description = $Description
                Server = $rwdcFQDN
                ErrorAction = 'Stop'
            }
            
            # Add any additional parameters (KerberosEncryptionType, ServicePrincipalNames, etc.)
            $setUserParams += $AdditionalParams
            
            Set-ADUser @setUserParams
            
            # Set account control flags
            if ($AccountControl.Count -gt 0) {
                $controlParams = @{
                    Identity = $samAccountName
                    Server = $rwdcFQDN
                    ErrorAction = 'Stop'
                }
                $controlParams += $AccountControl
                Set-ADAccountControl @controlParams
            }
            
            Write-Host "  Created: $Description" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "  ERROR: $Description - $_" -ForegroundColor Red
            return $false
        }
    }
    
    # PASSWORD NEVER EXPIRES
    if (New-BadUser -Description "USER WITH: PASSWORD NEVER EXPIRES" `
        -AccountControl @{ PasswordNeverExpires = $true }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # SENSITIVE AND NOT DELEGATABLE
    if (New-BadUser -Description "USER WITH: SENSITIVE AND NOT DELEGATABLE" `
        -AccountControl @{ AccountNotDelegated = $true }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # DOES NOT REQUIRE PRE-AUTH
    if (New-BadUser -Description "USER WITH: DOES NOT REQUIRE PRE-AUTH" `
        -AccountControl @{ DoesNotRequirePreAuth = $true }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # USE DES KEYS ONLY
    if (New-BadUser -Description "USER WITH: USE DES KEYS ONLY" `
        -AccountControl @{ UseDESKeyOnly = $true }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # PASSWORD NOT REQUIRED BUT WITH PASSWORD
    if (New-BadUser -Description "USER WITH: PASSWORD NOT REQUIRED BUT WITH PASSWORD" `
        -AccountControl @{ PasswordNotRequired = $true }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # PASSWORD NOT REQUIRED BUT WITHOUT PASSWORD
    if (New-BadUser -Description "USER WITH: PASSWORD NOT REQUIRED BUT WITHOUT PASSWORD" `
        -AccountControl @{ PasswordNotRequired = $true }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: DES
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: DES" `
        -AdditionalParams @{ KerberosEncryptionType = 'DES' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: RC4
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: RC4" `
        -AdditionalParams @{ KerberosEncryptionType = 'RC4' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: AES128
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: AES128" `
        -AdditionalParams @{ KerberosEncryptionType = 'AES128' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: AES256
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: AES256" `
        -AdditionalParams @{ KerberosEncryptionType = 'AES256' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: AES128,AES256
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: AES128,AES256" `
        -AdditionalParams @{ KerberosEncryptionType = 'AES128', 'AES256' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: RC4,AES128,AES256
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: RC4,AES128,AES256" `
        -AdditionalParams @{ KerberosEncryptionType = 'RC4', 'AES128', 'AES256' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: DES,RC4,AES128,AES256
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: DES,RC4,AES128,AES256" `
        -AdditionalParams @{ KerberosEncryptionType = 'DES', 'RC4', 'AES128', 'AES256' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: DES,AES256
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: DES,AES256" `
        -AdditionalParams @{ KerberosEncryptionType = 'DES', 'AES256' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # KERBEROS ENCRYPTION TYPE: DES,RC4
    if (New-BadUser -Description "USER WITH: KERBEROS ENCRYPTION TYPE: DES,RC4" `
        -AdditionalParams @{ KerberosEncryptionType = 'DES', 'RC4' }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # SPNs
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    if (New-BadUser -Description "USER WITH: SPNs" `
        -AdditionalParams @{ ServicePrincipalNames = @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" } }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # UNCONSTRAINED DELEGATION
    if (New-BadUser -Description "USER WITH: ACCOUNT BASED UNCONSTRAINED DELEGATION" `
        -AccountControl @{ TrustedForDelegation = $true }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # CONSTRAINED DELEGATION (ANY AUTH) NO SERVICES
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    if (New-BadUser -Description "USER WITH: ACCOUNT BASED CONSTRAINED DELEGATION (ANY AUTH) AND NO SERVICES LIST" `
        -AccountControl @{ TrustedToAuthForDelegation = $true } `
        -AdditionalParams @{ ServicePrincipalNames = @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" } }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # CONSTRAINED DELEGATION (ANY AUTH) WITH SERVICES
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    if (New-BadUser -Description "USER WITH: ACCOUNT BASED CONSTRAINED DELEGATION (ANY AUTH) AND SERVICES LIST" `
        -AccountControl @{ TrustedToAuthForDelegation = $true } `
        -AdditionalParams @{ 
            Add = @{ "msDS-AllowedToDelegateTo" = @("MSSQLSvc/$randomNr`:1433", "MSSQLSvc/$randomNr.$domainFQDN`:1433") }
            ServicePrincipalNames = @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" }
        }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # CONSTRAINED DELEGATION (ANY AUTH) WITH DC SERVICES
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    if (New-BadUser -Description "USER WITH: ACCOUNT BASED CONSTRAINED DELEGATION (ANY AUTH) AND SERVICES LIST (DC SERVICES)" `
        -AccountControl @{ TrustedToAuthForDelegation = $true } `
        -AdditionalParams @{ 
            Add = @{ "msDS-AllowedToDelegateTo" = @("HOST/$pdcFsmoFQDN", "GC/$pdcFsmoFQDN/$domainFQDN", "ldap/$pdcFsmoFQDN/$domainFQDN", "RestrictedKrbHost/$pdcFsmoFQDN") }
            ServicePrincipalNames = @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" }
        }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # CONSTRAINED DELEGATION (KERBEROS AUTH) WITH SERVICES
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    if (New-BadUser -Description "USER WITH: ACCOUNT BASED CONSTRAINED DELEGATION (KERBEROS AUTH) AND SERVICES LIST" `
        -AdditionalParams @{ 
            Add = @{ "msDS-AllowedToDelegateTo" = @("MSSQLSvc/$randomNr`:1433", "MSSQLSvc/$randomNr.$domainFQDN`:1433") }
            ServicePrincipalNames = @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" }
        }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # CONSTRAINED DELEGATION (KERBEROS AUTH) WITH DC SERVICES
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    if (New-BadUser -Description "USER WITH: ACCOUNT BASED CONSTRAINED DELEGATION (KERBEROS AUTH) AND SERVICES LIST (DC SERVICES)" `
        -AdditionalParams @{ 
            Add = @{ "msDS-AllowedToDelegateTo" = @("HOST/$pdcFsmoFQDN", "GC/$pdcFsmoFQDN/$domainFQDN", "ldap/$pdcFsmoFQDN/$domainFQDN", "RestrictedKrbHost/$pdcFsmoFQDN") }
            ServicePrincipalNames = @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" }
        }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # RESOURCE BASED DELEGATION
    $adminUser = Get-ADUser -Filter { SamAccountName -eq 'Administrator' } -ErrorAction SilentlyContinue
    if ($adminUser) {
        if (New-BadUser -Description "USER WITH: RESOURCE BASED DELEGATION" `
            -AdditionalParams @{ PrincipalsAllowedToDelegateToAccount = $adminUser }) {
            $successCount++
        } else { $skipCount++ }
    }
    Start-Sleep -s 1
    
    # PASSWORD REVERSIBLE ENCRYPTION BEFORE SETTING
    if (New-BadUser -Description "USER WITH: PASSWORD REVERSIBLE ENCRYPTION BEFORE SETTING" `
        -AccountControl @{ AllowReversiblePasswordEncryption = $true }) {
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # PASSWORD REVERSIBLE ENCRYPTION AFTER SETTING
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    $samAccountName = "USER$randomNr"
    $password = $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
    
    if (-not (Get-ADUser -Filter { SamAccountName -eq $samAccountName } -ErrorAction SilentlyContinue)) {
        try {
            New-ADUser -Path $testOU -Enabled $true -Name "USER$randomNr" -GivenName "USER" -Surname $randomNr `
                -DisplayName "USER$randomNr" -SamAccountName $samAccountName `
                -UserPrincipalName "USER.$randomNr@$domainFQDN" `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Server $rwdcFQDN -ErrorAction Stop
            
            Set-ADUser -Identity $samAccountName `
                -Description "USER WITH: PASSWORD REVERSIBLE ENCRYPTION AFTER SETTING" -Server $rwdcFQDN -ErrorAction Stop
            
            Set-ADAccountControl -Identity $samAccountName -AllowReversiblePasswordEncryption $true -Server $rwdcFQDN -ErrorAction Stop
            
            # Change password to trigger reversible encryption
            Set-ADAccountPassword -Identity $samAccountName `
                -NewPassword (ConvertTo-SecureString $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32)) -AsPlainText -Force) `
                -Server $rwdcFQDN -ErrorAction Stop
            
            Write-Host "  Created: USER WITH: PASSWORD REVERSIBLE ENCRYPTION AFTER SETTING" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "  ERROR: USER WITH: PASSWORD REVERSIBLE ENCRYPTION AFTER SETTING - $_" -ForegroundColor Red
            $skipCount++
        }
    } else {
        Write-Host "  Skipping (exists): USER WITH: PASSWORD REVERSIBLE ENCRYPTION AFTER SETTING" -ForegroundColor Yellow
        $skipCount++
    }
    Start-Sleep -s 1
    
    # COMPROMISED PASSWORD
    if (New-BadUser -Description "USER WITH: COMPROMISED PASSWORD") {
        $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
        $samAccountName = "USER$randomNr"
        Set-ADAccountPassword -Identity $samAccountName -NewPassword (ConvertTo-SecureString "welcome" -AsPlainText -Force) `
            -Server $rwdcFQDN -ErrorAction SilentlyContinue
        $successCount++
    } else { $skipCount++ }
    Start-Sleep -s 1
    
    # SMARTCARD REQUIRED (3 instances)
    for ($i = 0; $i -lt 3; $i++) {
        $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
        $samAccountName = "USER$randomNr"
        
        if (-not (Get-ADUser -Filter { SamAccountName -eq $samAccountName } -ErrorAction SilentlyContinue)) {
            try {
                New-ADUser -Path $testOU -Enabled $true -Name "USER$randomNr" -GivenName "USER" -Surname $randomNr `
                    -DisplayName "USER$randomNr" -SamAccountName $samAccountName `
                    -UserPrincipalName "USER.$randomNr@$domainFQDN" `
                    -AccountPassword (ConvertTo-SecureString "welcome" -AsPlainText -Force) -Server $rwdcFQDN -ErrorAction Stop
                
                Set-ADUser -Identity $samAccountName -SmartcardLogonRequired $true `
                    -Description "USER WITH: SMARTCARD REQUIRED" -Server $rwdcFQDN -ErrorAction Stop
                
                Write-Host "  Created: USER WITH: SMARTCARD REQUIRED (instance $($i+1))" -ForegroundColor Green
                $successCount++
            }
            catch {
                Write-Host "  ERROR: USER WITH: SMARTCARD REQUIRED (instance $($i+1)) - $_" -ForegroundColor Red
                $skipCount++
            }
        } else {
            Write-Host "  Skipping (exists): USER WITH: SMARTCARD REQUIRED (instance $($i+1))" -ForegroundColor Yellow
            $skipCount++
        }
        Start-Sleep -s 1
    }
    
    Write-Host ""
    Write-Host "User account summary:" -ForegroundColor Cyan
    Write-Host "  Created: $successCount" -ForegroundColor Green
    Write-Host "  Skipped: $skipCount" -ForegroundColor Yellow
    Write-Host ""
}

Export-ModuleMember -Function Invoke-AccountSecurityUsers