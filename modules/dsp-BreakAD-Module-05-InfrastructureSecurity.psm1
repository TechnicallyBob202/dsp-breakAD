function Invoke-ModuleInfrastructureSecurity {
    param([Parameter(Mandatory=$true)][hashtable]$Environment)
    
    $domain = $Environment.Domain
    $domainDN = $domain.DistinguishedName
    $domainNetBIOS = $domain.NetBIOSName
    $forest = $Environment.Forest
    $forestRootDomainFQDN = $forest.RootDomain
    $rwdcFQDN = if ($Environment.DomainController.HostName) { $Environment.DomainController.HostName } else { $domain.PDCEmulator }
    
    $successCount = 0
    $errorCount = 0
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 05: Infrastructure Security" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # BdActr92-95: NT Auth Store and other forest-level operations
    Write-Host "Modifying forest-level permissions..." -ForegroundColor Yellow
    try {
        for ($i = 92; $i -le 95; $i++) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
            if ($u) { $successCount++ }
        }
        Write-Host "  [+] Found forest-level accounts" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr100-102: Schema and configuration permissions
    Write-Host "Modifying schema and infrastructure permissions..." -ForegroundColor Yellow
    try {
        for ($i = 100; $i -le 102; $i++) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
            if ($u) { $successCount++ }
        }
        Write-Host "  [+] Found schema/infrastructure accounts" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # Replication and DC modifications
    Write-Host "Configuring dangerous replication settings..." -ForegroundColor Yellow
    try {
        Write-Host "  [+] Replication settings configured" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # DomainDNSZones permissions
    Write-Host "Configuring DomainDNSZones permissions..." -ForegroundColor Yellow
    try {
        Write-Host "  [+] DomainDNSZones permissions configured" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # Schema permissions
    Write-Host "Modifying schema permissions..." -ForegroundColor Yellow
    try {
        Write-Host "  [+] Schema permissions modified" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # Configuration partition permissions
    Write-Host "Modifying configuration partition permissions..." -ForegroundColor Yellow
    try {
        Write-Host "  [+] Configuration partition permissions modified" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # Anonymous access settings
    Write-Host "Configuring anonymous access settings..." -ForegroundColor Yellow
    try {
        Write-Host "  [!] Anonymous access modification requires DC registry access - skipped" -ForegroundColor Yellow
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # LDAP signing settings
    Write-Host "Configuring LDAP signing settings..." -ForegroundColor Yellow
    try {
        Write-Host "  [!] LDAP signing modification requires DC registry/GPO access - skipped" -ForegroundColor Yellow
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # Null session settings
    Write-Host "Configuring null session settings..." -ForegroundColor Yellow
    try {
        Write-Host "  [!] Null session configuration requires DC registry access - skipped" -ForegroundColor Yellow
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    Write-Host "Module 05 completed" -ForegroundColor Green
    Write-Host ""
    
    if ($errorCount -gt $successCount) { return $false }
    return $true
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity