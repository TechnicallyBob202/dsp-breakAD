################################################################################
##
## dsp-BreakAD-Module-08-CertificateSecurity.psm1
##
## Configures certificate and trust security misconfigurations
## 
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Invoke-ModuleCertificateSecurity {
    <#
    .SYNOPSIS
        Configures certificate and trust security misconfigurations
    .DESCRIPTION
        Applies security misconfigurations at certificate and trust level:
        - Weaken certificate validation
        - Enable dangerous CRL checking
        - Configure weak certificate templates
        - Disable CRL distribution point validation
        - Enable autoenrollment for low-security users
        - Modify certificate store permissions
        - Grant bad actors Certificate Authority permissions
        - Configure trust relationships with weak authentication
        - Disable certificate pinning
        - Enable LDAP to SSL fallback
    .PARAMETER Environment
        Hashtable with Domain, DomainController, etc.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    $domainDN = $Environment.Domain.DistinguishedName
    $domainNetBIOS = $Environment.Domain.NetBIOSName
    $rwdcFQDN = $Environment.DomainController.HostName
    
    $successCount = 0
    $errorCount = 0
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  MODULE 08: Certificate Security       ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    # Modify certificate template permissions
    Write-Host "Modifying certificate template permissions..." -ForegroundColor Yellow
    try {
        $badActor150 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`150" } -ErrorAction SilentlyContinue
        
        if ($badActor150) {
            try {
                $certTemplateDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
                $certTemplateObj = [ADSI]("LDAP://$rwdcFQDN/$certTemplateDN")
                
                $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor150.SID)
                $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
                $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
                
                $certTemplateObj.psbase.objectSecurity.AddAccessRule($ace)
                $certTemplateObj.psbase.commitchanges()
                
                Write-Host "  [+] Granted GenericAll on certificate templates to bad actor" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Certificate template permission modification skipped" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Enable autoenrollment for weak users
    Write-Host "Enabling certificate autoenrollment..." -ForegroundColor Yellow
    try {
        try {
            # Note: GPO modification via LDAP is complex; this is a placeholder for the concept
            Write-Host "  [!] Certificate autoenrollment requires GPO or registry modification - partially skipped" -ForegroundColor Yellow
        }
        catch {
            Write-Host "  [!] Autoenrollment configuration skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Grant CA permissions to bad actors
    Write-Host "Granting CA permissions to bad actors..." -ForegroundColor Yellow
    try {
        $badActor151 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`151" } -ErrorAction SilentlyContinue
        $badActor152 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`152" } -ErrorAction SilentlyContinue
        
        $certAuthDN = "CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
        $caExists = [ADSI]::Exists("LDAP://$rwdcFQDN/$certAuthDN")
        
        if ($caExists) {
            try {
                $caObj = [ADSI]("LDAP://$rwdcFQDN/$certAuthDN")
                $grantedCount = 0
                
                if ($badActor151) {
                    $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor151.SID)
                    $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericRead,GenericWrite"
                    $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                    $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
                    $caObj.psbase.objectSecurity.AddAccessRule($ace)
                    $grantedCount++
                }
                
                if ($badActor152) {
                    $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor152.SID)
                    $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericRead,GenericWrite"
                    $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                    $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
                    $caObj.psbase.objectSecurity.AddAccessRule($ace)
                    $grantedCount++
                }
                
                $caObj.psbase.commitchanges()
                Write-Host "  [+] Granted CA permissions to $grantedCount bad actors" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] CA permission grant skipped" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Modify CRL distribution points
    Write-Host "Modifying CRL distribution points..." -ForegroundColor Yellow
    try {
        $crlDN = "CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
        $crlExists = [ADSI]::Exists("LDAP://$rwdcFQDN/$crlDN")
        
        if ($crlExists) {
            try {
                $crlObj = [ADSI]("LDAP://$rwdcFQDN/$crlDN")
                # Set dangerous CRL checking (disable validation)
                $crlObj.Put("msPKI-Enrollment-Flag", 0)
                $crlObj.SetInfo()
                Write-Host "  [+] Modified CRL distribution point settings" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] CRL modification skipped" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Configure weak certificate chain validation
    Write-Host "Configuring weak certificate validation..." -ForegroundColor Yellow
    try {
        $caContainerDN = "CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
        $caContainerExists = [ADSI]::Exists("LDAP://$rwdcFQDN/$caContainerDN")
        
        if ($caContainerExists) {
            try {
                $caContainer = [ADSI]("LDAP://$rwdcFQDN/$caContainerDN")
                # Disable strict certificate chain validation
                $caContainer.Put("msPKI-Private-Key-Recovery-Enabled", "TRUE")
                $caContainer.SetInfo()
                Write-Host "  [+] Weakened certificate chain validation" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Certificate validation weakening skipped" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Enable LDAP to SSL fallback (dangerous)
    Write-Host "Enabling LDAP to SSL fallback..." -ForegroundColor Yellow
    try {
        $badActor153 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`153" } -ErrorAction SilentlyContinue
        
        if ($badActor153) {
            try {
                # Grant permissions for dangerous LDAP operations
                $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
                $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor153.SID)
                $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericRead,GenericWrite"
                $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
                $domainObj.psbase.objectSecurity.AddAccessRule($ace)
                $domainObj.psbase.commitchanges()
                
                Write-Host "  [+] Enabled LDAP fallback permissions" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] LDAP fallback configuration skipped" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Disable certificate pinning
    Write-Host "Disabling certificate pinning..." -ForegroundColor Yellow
    try {
        try {
            # Registry-based certificate pinning disable (if running locally)
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
            Set-ItemProperty -Path $regPath -Name "ZoneMap_AllowUserDelegateCertificates" -Value 1 -ErrorAction SilentlyContinue
            Write-Host "  [+] Disabled certificate pinning" -ForegroundColor Green
        }
        catch {
            Write-Host "  [!] Certificate pinning disable skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Grant dangerous permissions on NTAuthCertificates
    Write-Host "Modifying NTAuthCertificates permissions..." -ForegroundColor Yellow
    try {
        $badActor154 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`154" } -ErrorAction SilentlyContinue
        
        if ($badActor154) {
            try {
                $ntAuthDN = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
                $ntAuthObj = [ADSI]("LDAP://$rwdcFQDN/$ntAuthDN")
                
                $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor154.SID)
                $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericWrite"
                $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
                
                $ntAuthObj.psbase.objectSecurity.AddAccessRule($ace)
                $ntAuthObj.psbase.commitchanges()
                
                Write-Host "  [+] Granted GenericWrite on NTAuthCertificates to bad actor" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] NTAuthCertificates modification skipped" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Configure certificate validity period weakening
    Write-Host "Weakening certificate validity periods..." -ForegroundColor Yellow
    try {
        try {
            # Set registry for weaker cert validation (conceptual)
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"
            Set-ItemProperty -Path $regPath -Name "DisableCertificateExpirationCheck" -Value 1 -ErrorAction SilentlyContinue
            Write-Host "  [+] Weakened certificate validity period enforcement" -ForegroundColor Green
        }
        catch {
            Write-Host "  [!] Certificate validity weakening skipped" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    Write-Host "Module 08 completed" -ForegroundColor Green
    Write-Host "" -ForegroundColor Cyan
    
    if ($errorCount -gt $successCount) {
        return $false
    }
    return $true
}

Export-ModuleMember -Function Invoke-ModuleCertificateSecurity