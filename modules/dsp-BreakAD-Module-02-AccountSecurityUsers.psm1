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

function Invoke-ModuleAccountSecurityUsers {
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
    
    $domainDN = $Environment.Domain.DistinguishedName
    $domainFQDN = $Environment.Domain.DNSRoot
    $rwdcFQDN = $Environment.DomainController.HostName
    
    # Ensure TEST OU exists
    $testOU = "OU=TEST,$domainDN"
    if (-not (Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $testOU } -ErrorAction SilentlyContinue)) {
        Write-Log "Creating TEST OU..." -Level INFO
        New-ADOrganizationalUnit -Name "TEST" -Path $domainDN -ErrorAction SilentlyContinue
    }
    
    Write-Log "Creating user accounts with bad security configurations..." -Level INFO
    Write-Log "" -Level INFO
    
    $successCount = 0
    $skipCount = 0
    
    # PASSWORD NEVER EXPIRES
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    $samAccountName = "USER$randomNr"
    if (-not (Get-ADUser -Filter { SamAccountName -eq $samAccountName } -ErrorAction SilentlyContinue)) {
        try {
            $password = $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
            New-ADUser -Path $testOU -Enabled $true -Name "USER$randomNr" -GivenName "USER" -Surname $randomNr `
                -DisplayName "USER$randomNr" -SamAccountName $samAccountName -UserPrincipalName "USER.$randomNr@$domainFQDN" `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PasswordNeverExpires $true `
                -Description "USER WITH: PASSWORD NEVER EXPIRES" -Server $rwdcFQDN -ErrorAction Stop
            Write-Log "  Created: USER WITH: PASSWORD NEVER EXPIRES" -Level SUCCESS
            $successCount++
        }
        catch { 
            Write-Log "  ERROR: USER WITH: PASSWORD NEVER EXPIRES - $_" -Level ERROR
            $skipCount++
        }
    }
    Start-Sleep -s 1
    
    # SENSITIVE AND NOT DELEGATABLE
    $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 10 -Maximum 99)
    $samAccountName = "USER$randomNr"
    if (-not (Get-ADUser -Filter { SamAccountName -eq $samAccountName } -ErrorAction SilentlyContinue)) {
        try {
            $password = $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
            New-ADUser -Path $testOU -Enabled $true -Name "USER$randomNr" -GivenName "USER" -Surname $randomNr `
                -DisplayName "USER$randomNr" -SamAccountName $samAccountName -UserPrincipalName "USER.$randomNr@$domainFQDN" `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNotDelegated $true `
                -Description "USER WITH: SENSITIVE AND NOT DELEGATABLE" -Server $rwdcFQDN -ErrorAction Stop
            Write-Log "  Created: USER WITH: SENSITIVE AND NOT DELEGATABLE" -Level SUCCESS
            $successCount++
        }
        catch { 
            Write-Log "  ERROR: USER WITH: SENSITIVE AND NOT DELEGATABLE - $_" -Level ERROR
            $skipCount++
        }
    }
    Start-Sleep -s 1
    
    Write-Log "" -Level INFO
    Write-Log "User account summary:" -Level INFO
    Write-Log "  Created: $successCount" -Level SUCCESS
    Write-Log "  Skipped: $skipCount" -Level WARNING
    Write-Log "" -Level INFO
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurityUsers