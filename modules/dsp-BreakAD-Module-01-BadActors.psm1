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
    
    $domain = $Environment.Domain
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    $domainNetBIOS = $domain.NetBIOSName
    $pdcFsmoFQDN = $domain.PDCEmulator
    $rwdcFQDN = $Environment.DomainController.HostName
    
    # Ensure TEST OU exists
    $testOU = "OU=TEST,$domainDN"
    if (-not (Get-ADOrganizationalUnit -Filter { DistinguishedName -eq $testOU } -ErrorAction SilentlyContinue)) {
        Write-Host "Creating TEST OU..." -ForegroundColor Cyan
        New-ADOrganizationalUnit -Name "TEST" -Path $domainDN -ErrorAction SilentlyContinue
    }
    
    Write-Host "Creating 200 Bad Actor accounts in TEST OU..." -ForegroundColor Cyan
    Write-Host ""
    
    $successCount = 0
    $skipCount = 0
    
    0..200 | ForEach-Object {
        $index = $_
        $samAccountName = "BdActr$domainNetBIOS$index"
        
        # Check if account already exists
        $existing = Get-ADUser -Filter { SamAccountName -eq $samAccountName } -ErrorAction SilentlyContinue
        if ($existing) {
            $skipCount++
            Write-Host "  [$($index + 1)/201] Skipping (already exists): $samAccountName" -ForegroundColor Yellow
            return
        }
        
        try {
            # Generate random password
            $randomNr = (Get-Date -Format "yyyyMMddHHmmss").ToString() + (Get-Random -Minimum 100 -Maximum 999)
            $password = $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
            
            # Create the user
            New-ADUser `
                -Path $testOU `
                -Enabled $true `
                -Name "Bad Act0r $domainFQDN $index" `
                -GivenName "Bad" `
                -Surname "Act0r $domainFQDN $index" `
                -DisplayName "Bad Act0r $domainFQDN $index" `
                -SamAccountName $samAccountName `
                -UserPrincipalName "Bad.Act0r.$domainFQDN.$index@$domainFQDN" `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                -Server $rwdcFQDN `
                -ErrorAction Stop
            
            # Apply additional risky configurations based on account number
            if ($index.ToString().EndsWith("1")) {
                # SQL delegation
                Set-ADUser `
                    -Identity $samAccountName `
                    -Description "Bad Act0r $domainFQDN $index Password = $password" `
                    -Add @{ "msDS-AllowedToDelegateTo" = @("MSSQLSvc/$randomNr`:1433", "MSSQLSvc/$randomNr.$domainFQDN`:1433") } `
                    -ServicePrincipalNames @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" } `
                    -Server $rwdcFQDN `
                    -ErrorAction Stop
            }
            elseif ($index.ToString().EndsWith("2")) {
                # DC delegation
                Set-ADUser `
                    -Identity $samAccountName `
                    -Description "Bad Act0r $domainFQDN $index Password = $password" `
                    -Add @{ "msDS-AllowedToDelegateTo" = @("HOST/$pdcFsmoFQDN", "GC/$pdcFsmoFQDN/$domainFQDN", "ldap/$pdcFsmoFQDN/$domainFQDN", "RestrictedKrbHost/$pdcFsmoFQDN") } `
                    -ServicePrincipalNames @{ Add = "HTTP/$randomNr.111.$domainFQDN", "HTTP/$randomNr.222.$domainFQDN" } `
                    -Server $rwdcFQDN `
                    -ErrorAction Stop
            }
            else {
                # Basic bad actor
                Set-ADUser `
                    -Identity $samAccountName `
                    -Description "Bad Act0r $domainFQDN $index Password = $password" `
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
            Write-Host "  [$($index + 1)/201] Created: $samAccountName" -ForegroundColor Green
        }
        catch {
            Write-Host "  [$($index + 1)/201] ERROR creating $samAccountName`: $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Bad Actor accounts summary:" -ForegroundColor Cyan
    Write-Host "  Created: $successCount" -ForegroundColor Green
    Write-Host "  Skipped: $skipCount" -ForegroundColor Yellow
    Write-Host ""
}

Export-ModuleMember -Function Invoke-ModuleBadActors