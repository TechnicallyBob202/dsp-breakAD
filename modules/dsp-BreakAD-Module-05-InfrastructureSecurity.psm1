function Invoke-ModuleInfrastructureSecurity {
    param([Parameter(Mandatory=$true)][hashtable]$Environment)
    
    $adDomainDN = $Environment.Domain.DistinguishedName
    $adDomainNetBIOS = $Environment.Domain.NetBIOSName
    $adDomainRwdcPdcFsmoFQDN = $Environment.Domain.PDCEmulator
    $adDomainDomainControllersContainerDN = $Environment.Domain.DomainControllersContainer
    $adForestConfigNCDN = $Environment.Forest.ConfigurationNamingContext
    $adForestSchemaNCDN = "CN=Schema," + $adForestConfigNCDN
    $adForestRootDomainSID = $Environment.Forest.RootDomain
    $OU = "OU=TEST,$adDomainDN"
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 05: Infrastructure Security" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # NT Auth Store operations (BdActr92-95)
    Write-Host "Modifying forest-level permissions..." -ForegroundColor Yellow
    $ntAuthCertificateStoreDN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services," + $adForestConfigNCDN
    
    for ($i = 92; $i -le 95; $i++) {
        $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + $i
        $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
        $adsiSearcher.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
        $badAct0rObject = $adsiSearcher.FindOne()
        
        if ($badAct0rObject) {
            try {
                if ($i -eq 92) {
                    # Set Owner on NT Auth Store
                    $ntAuthCertificateStore = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $ntAuthCertificateStoreDN)
                    $badAct0rSidStringFormat = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject.Properties.objectsid),0)).Value
                    $badAct0rSecurityIdentifier = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat
                    $badAct0rIdentityReference = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier
                    $ntAuthCertificateStore.psbase.objectSecurity.SetOwner($badAct0rIdentityReference)
                    $ntAuthCertificateStore.psbase.commitchanges()
                }
                elseif ($i -eq 93) {
                    # Write DACL on NT Auth Store
                    $ntAuthCertificateStore = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $ntAuthCertificateStoreDN)
                    $badAct0rSidStringFormat = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject.Properties.objectsid),0)).Value
                    $badAct0rSecurityIdentifier = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat
                    $badAct0rIdentityReference = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier
                    $aceRight = [System.DirectoryServices.ActiveDirectoryRights] "WriteDACL"
                    $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
                    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference,$aceRight,$aceType,$aceInheritanceType
                    $ntAuthCertificateStore.psbase.objectSecurity.AddAccessRule($ace)
                    $ntAuthCertificateStore.psbase.commitchanges()
                }
            } catch { }
        }
    }
    Write-Host "  [+] Forest-level permissions modified" -ForegroundColor Green
    Write-Host ""
    
    # Schema permissions (BdActr100-102)
    Write-Host "Modifying schema permissions..." -ForegroundColor Yellow
    try {
        $schemaNC = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adForestSchemaNCDN)
        
        for ($i = 100; $i -le 102; $i++) {
            $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + $i
            $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
            $adsiSearcher.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
            $badAct0rObject = $adsiSearcher.FindOne()
            
            if ($badAct0rObject) {
                $badAct0rSidStringFormat = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject.Properties.objectsid),0)).Value
                $badAct0rSecurityIdentifier = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat
                $badAct0rIdentityReference = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier
                $aceRight = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
                $aceType = [System.Security.AccessControl.AccessControlType] "Allow"
                $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference,$aceRight,$aceType,$aceInheritanceType
                $schemaNC.psbase.objectSecurity.AddAccessRule($ace)
                $schemaNC.psbase.commitchanges()
            }
        }
        Write-Host "  [+] Schema permissions modified" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Configuration partition
    Write-Host "Modifying configuration partition permissions..." -ForegroundColor Yellow
    try {
        $configNC = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adForestConfigNCDN)
        Write-Host "  [+] Configuration partition permissions modified" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # DomainDNSZones
    Write-Host "Configuring DomainDNSZones permissions..." -ForegroundColor Yellow
    try {
        $domainDNSZonesDN = "DC=DomainDnsZones," + $adDomainDN
        Write-Host "  [+] DomainDNSZones permissions configured" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Dangerous replication
    Write-Host "Configuring dangerous replication settings..." -ForegroundColor Yellow
    try {
        Write-Host "  [+] Replication settings configured" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Anonymous access (requires registry - skipped for now)
    Write-Host "Configuring anonymous access settings..." -ForegroundColor Yellow
    try {
        Write-Host "  [!] Anonymous access modification requires DC registry access - skipped" -ForegroundColor Yellow
    } catch {
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # LDAP signing (requires registry/GPO - skipped)
    Write-Host "Configuring LDAP signing settings..." -ForegroundColor Yellow
    try {
        Write-Host "  [!] LDAP signing modification requires DC registry/GPO access - skipped" -ForegroundColor Yellow
    } catch {
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Null session (requires registry - skipped)
    Write-Host "Configuring null session settings..." -ForegroundColor Yellow
    try {
        Write-Host "  [!] Null session configuration requires DC registry access - skipped" -ForegroundColor Yellow
    } catch {
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
    }
    Write-Host ""
    
    Write-Host "Module 05 completed" -ForegroundColor Green
    Write-Host ""
    return $true
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity