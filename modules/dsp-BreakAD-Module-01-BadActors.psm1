################################################################################
##
## dsp-BreakAD-Module-01-BadActors.psm1
##
## Creates 200 "Bad Actor" accounts with various security misconfigurations
## 
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Invoke-ModuleBadActors {
    <#
    .SYNOPSIS
        Creates bad actor user accounts with security misconfigurations
    
    .DESCRIPTION
        Creates 200 user accounts in the TEST OU with various risky configurations:
        - Users 1, 51, 101, 151: Kerberos delegation to SQL services
        - Users 2, 52, 102, 152: Kerberos delegation to DC services
        - Others: Basic users
        
        All accounts have password never expires enabled.
    
    .PARAMETER Environment
        Hashtable containing domain information from preflight checks
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domainDN = $Environment.Domain.DistinguishedName
    $domainFQDN = $Environment.Domain.DNSRoot
    $domainNetBIOS = $Environment.Domain.NetBIOSName
    $pdcFsmoFQDN = $Environment.Domain.PDCEmulator
    $rwdcFQDN = if ($Environment.DomainController.HostName) { $Environment.DomainController.HostName } else { $pdcFsmoFQDN }
    
    # Ensure TEST OU exists
    $testOU = "OU=TEST,$domainDN"
    if (-not (Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $testOU } -ErrorAction SilentlyContinue)) {
        Write-Host "Creating TEST OU..." -ForegroundColor Cyan
        New-ADOrganizationalUnit -Name "TEST" -Path $domainDN -ErrorAction SilentlyContinue
    }
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 01: Bad Actor Accounts" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Creating 200 Bad Actor accounts in TEST OU..." -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    
    $successCount = 0
    $skipCount = 0
    
    # Create 0-200 (201 total accounts) to cover all module needs
    # This creates BdActrD30, BdActrD31, ..., BdActrD3200
    for ($i = 0; $i -le 200; $i++) {
        $samAccountName = "BdActr$domainNetBIOS$i"
        
        # Check if account already exists
        $existing = Get-ADUser -Filter { SamAccountName -eq $samAccountName } -ErrorAction SilentlyContinue
        if ($existing) {
            $skipCount++
            Write-Host "  [$($i + 1)/201] Skipping (already exists): $samAccountName" -ForegroundColor Yellow
            continue
        }
        
        try {
            # Generate random password
            $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 100 -Maximum 999)
            $password = $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
            
            # Create the user
            New-ADUser `
                -Path $testOU `
                -Enabled $true `
                -Name "Bad Act0r $domainFQDN $i" `
                -GivenName "Bad" `
                -Surname "Act0r $domainFQDN $i" `
                -DisplayName "Bad Act0r $domainFQDN $i" `
                -SamAccountName $samAccountName `
                -UserPrincipalName "Bad.Act0r.$domainFQDN.$i@$domainFQDN" `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                -Server $rwdcFQDN `
                -ErrorAction Stop
            
            # Apply additional risky configurations based on account number
            if ($i.ToString().EndsWith("1")) {
                # SQL delegation
                Set-ADUser `
                    -Identity $samAccountName `
                    -Description "Bad Act0r $domainFQDN $i Password = $password" `
                    -Add @{ "msDS-AllowedToDelegateTo" = @("MSSQLSvc/$randomNr`:1433", "MSSQLSvc/$randomNr.$domainFQDN`:1433") } `
                    -ServicePrincipalNames @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" } `
                    -Server $rwdcFQDN `
                    -ErrorAction Stop
            }
            elseif ($i.ToString().EndsWith("2")) {
                # DC delegation
                Set-ADUser `
                    -Identity $samAccountName `
                    -Description "Bad Act0r $domainFQDN $i Password = $password" `
                    -Add @{ "msDS-AllowedToDelegateTo" = @("HOST/$pdcFsmoFQDN", "GC/$pdcFsmoFQDN/$domainFQDN", "ldap/$pdcFsmoFQDN/$domainFQDN", "RestrictedKrbHost/$pdcFsmoFQDN") } `
                    -ServicePrincipalNames @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" } `
                    -Server $rwdcFQDN `
                    -ErrorAction Stop
            }
            else {
                # Basic bad actor
                Set-ADUser `
                    -Identity $samAccountName `
                    -Description "Bad Act0r $domainFQDN $i Password = $password" `
                    -Server $rwdcFQDN `
                    -ErrorAction Stop
            }
            
            # Set password never expires
            Set-ADAccountControl `
                -Identity $samAccountName `
                -PasswordNeverExpires $true `
                -Server $rwdcFQDN `
                -ErrorAction Stop
            
            $successCount++
            Write-Host "  [$($i + 1)/201] Created: $samAccountName" -ForegroundColor Green
        }
        catch {
            Write-Host "  [$($i + 1)/201] ERROR creating $samAccountName`: $_" -ForegroundColor Red
        }
    }
    
    Write-Host "" -ForegroundColor Cyan
    Write-Host "Bad Actor accounts summary:" -ForegroundColor Cyan
    Write-Host "  Created: $successCount" -ForegroundColor Green
    Write-Host "  Skipped: $skipCount" -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Cyan
}

Export-ModuleMember -Function Invoke-ModuleBadActors