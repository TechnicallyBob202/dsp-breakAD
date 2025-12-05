################################################################################
##
## dsp-BreakAD-Module-04-KerberosSecurity.psm1
##
## Configures Kerberos security misconfigurations
## - Create users/computers with DES encryption only
## - Create users with RC4 encryption only
## - Multiple weak encryption options
## - Disable pre-auth on computer accounts
## - Create weak service principals
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleKerberosSecurity {
    <#
    .SYNOPSIS
        Applies Kerberos security misconfigurations
    
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
    
    Write-Log "Kerberos Security Module Starting" -Level INFO
    Write-Log "Domain: $($domain.Name)" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # DES ENCRYPTION ONLY
    ################################################################################
    
    if ($config['KerberosSecurity_IncludeDESEncryption'] -eq 'true') {
        Write-Log "Creating user with DES encryption only..." -Level INFO
        
        try {
            $userName = "break-DES-User"
            $password = ConvertTo-SecureString "DESPassword123!" -AsPlainText -Force
            
            # Check if exists
            $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                New-ADUser -Name $userName `
                    -SamAccountName $userName `
                    -AccountPassword $password `
                    -Enabled $true `
                    -ErrorAction Stop
                
                Write-Log "  [+] User created: $userName" -Level SUCCESS
            }
            
            $user = Get-ADUser -Identity $userName -ErrorAction Stop
            
            # Set to DES only (value = 1)
            Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 1} -ErrorAction Stop
            Write-LogChange -Object $userName -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "DES Only (1)"
            Write-Log "  [+] Encryption set to DES only" -Level SUCCESS
            $successCount++
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # RC4 ENCRYPTION ONLY
    ################################################################################
    
    if ($config['KerberosSecurity_IncludeRC4Encryption'] -eq 'true') {
        Write-Log "Creating user with RC4 encryption only..." -Level INFO
        
        try {
            $userName = "break-RC4-User"
            $password = ConvertTo-SecureString "RC4Password123!" -AsPlainText -Force
            
            # Check if exists
            $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                New-ADUser -Name $userName `
                    -SamAccountName $userName `
                    -AccountPassword $password `
                    -Enabled $true `
                    -ErrorAction Stop
                
                Write-Log "  [+] User created: $userName" -Level SUCCESS
            }
            
            $user = Get-ADUser -Identity $userName -ErrorAction Stop
            
            # Set to RC4 only (value = 4)
            Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 4} -ErrorAction Stop
            Write-LogChange -Object $userName -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "RC4 Only (4)"
            Write-Log "  [+] Encryption set to RC4 only" -Level SUCCESS
            $successCount++
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # MULTIPLE WEAK ENCRYPTIONS
    ################################################################################
    
    if ($config['KerberosSecurity_IncludeMultipleWeakEncryptions'] -eq 'true') {
        Write-Log "Creating user with DES + RC4 encryption..." -Level INFO
        
        try {
            $userName = "break-Weak-Encryption-User"
            $password = ConvertTo-SecureString "WeakEncryption123!" -AsPlainText -Force
            
            # Check if exists
            $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                New-ADUser -Name $userName `
                    -SamAccountName $userName `
                    -AccountPassword $password `
                    -Enabled $true `
                    -ErrorAction Stop
                
                Write-Log "  [+] User created: $userName" -Level SUCCESS
            }
            
            $user = Get-ADUser -Identity $userName -ErrorAction Stop
            
            # Set to DES + RC4 (value = 5: 1 + 4)
            Set-ADUser -Identity $user -Replace @{"msDS-SupportedEncryptionTypes" = 5} -ErrorAction Stop
            Write-LogChange -Object $userName -Attribute "msDS-SupportedEncryptionTypes" -OldValue "Default" -NewValue "DES + RC4 (5)"
            Write-Log "  [+] Encryption set to DES + RC4" -Level SUCCESS
            $successCount++
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # DISABLE PRE-AUTH ON COMPUTERS
    ################################################################################
    
    if ($config['KerberosSecurity_DisableComputerPreAuth'] -eq 'true') {
        Write-Log "Disabling pre-auth on computer accounts..." -Level INFO
        
        try {
            $computerName = "BREAK-NOAUTH"
            
            # Check if exists
            $existingComputer = Get-ADComputer -Identity $computerName -ErrorAction SilentlyContinue
            if (-not $existingComputer) {
                New-ADComputer -Name $computerName -Enabled $true -ErrorAction Stop
                Write-Log "  [+] Computer created: $computerName" -Level SUCCESS
            }
            
            $computer = Get-ADComputer -Identity $computerName -ErrorAction Stop
            
            # Disable pre-auth
            Set-ADComputer -Identity $computer -DoesNotRequirePreAuth $true -ErrorAction Stop
            Write-LogChange -Object $computerName -Attribute "DoesNotRequirePreAuth" -OldValue "False" -NewValue "True"
            Write-Log "  [+] Pre-auth disabled on $computerName" -Level SUCCESS
            $successCount++
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # WEAK SERVICE PRINCIPALS
    ################################################################################
    
    if ($config['KerberosSecurity_IncludeWeakSPNs'] -eq 'true') {
        Write-Log "Creating service principal with weak settings..." -Level INFO
        
        try {
            $userName = "break-SPN-User"
            $password = ConvertTo-SecureString "SPNPassword123!" -AsPlainText -Force
            
            # Check if exists
            $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
            if (-not $existingUser) {
                New-ADUser -Name $userName `
                    -SamAccountName $userName `
                    -AccountPassword $password `
                    -Enabled $true `
                    -ErrorAction Stop
                
                Write-Log "  [+] User created: $userName" -Level SUCCESS
            }
            
            $user = Get-ADUser -Identity $userName -ErrorAction Stop
            
            # Add SPNs
            $spns = @(
                "HTTP/break-web.corp.local",
                "LDAP/break-dc.corp.local",
                "MSSQLSvc/break-sql.corp.local:1433"
            )
            
            Set-ADUser -Identity $user -ServicePrincipalNames @{Add = $spns} -ErrorAction Stop
            
            # Disable pre-auth on this SPN user
            Set-ADUser -Identity $user -DoesNotRequirePreAuth $true -ErrorAction Stop
            
            Write-LogChange -Object $userName -Attribute "ServicePrincipalNames" -OldValue "None" -NewValue "$($spns -join ', ')"
            Write-LogChange -Object $userName -Attribute "DoesNotRequirePreAuth" -OldValue "False" -NewValue "True"
            Write-Log "  [+] Service principal created with weak settings" -Level SUCCESS
            $successCount++
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # SUMMARY
    ################################################################################
    
    Write-Log "Kerberos Security Module Complete" -Level INFO
    Write-Log "Successful changes: $successCount" -Level SUCCESS
    if ($errorCount -gt 0) {
        Write-Log "Errors encountered: $errorCount" -Level WARNING
        return $false
    }
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleKerberosSecurity