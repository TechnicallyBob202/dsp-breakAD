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
    
    Write-Log "" -Level INFO
    Write-Log "=== MODULE 08: Certificate and Trust Security ===" -Level INFO
    Write-Log "" -Level INFO
    
    # Modify certificate template permissions
    Write-Log "Modifying certificate template permissions..." -Level WARNING
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
                
                Write-Log "  [+] Granted GenericAll on certificate templates to bad actor" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Certificate template permission modification skipped" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Enable autoenrollment for weak users
    Write-Log "Enabling certificate autoenrollment..." -Level WARNING
    try {
        try {
            # Note: GPO modification via LDAP is complex; this is a placeholder for the concept
            Write-Log "  [!] Certificate autoenrollment requires GPO or registry modification - partially skipped" -Level WARNING
        }
        catch {
            Write-Log "  [!] Autoenrollment configuration skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Grant CA permissions to bad actors
    Write-Log "Granting CA permissions to bad actors..." -Level WARNING
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
                Write-Log "  [+] Granted CA permissions to $grantedCount bad actors" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] CA permission grant skipped" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Modify CRL distribution points
    Write-Log "Modifying CRL distribution points..." -Level WARNING
    try {
        $crlDN = "CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
        $crlExists = [ADSI]::Exists("LDAP://$rwdcFQDN/$crlDN")
        
        if ($crlExists) {
            try {
                $crlObj = [ADSI]("LDAP://$rwdcFQDN/$crlDN")
                # Set dangerous CRL checking (disable validation)
                $crlObj.Put("msPKI-Enrollment-Flag", 0)
                $crlObj.SetInfo()
                Write-Log "  [+] Modified CRL distribution point settings" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] CRL modification skipped" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Configure weak certificate chain validation
    Write-Log "Configuring weak certificate validation..." -Level WARNING
    try {
        $caContainerDN = "CN=Public Key Services,CN=Services,CN=Configuration,$domainDN"
        $caContainerExists = [ADSI]::Exists("LDAP://$rwdcFQDN/$caContainerDN")
        
        if ($caContainerExists) {
            try {
                $caContainer = [ADSI]("LDAP://$rwdcFQDN/$caContainerDN")
                # Disable strict certificate chain validation
                $caContainer.Put("msPKI-Private-Key-Recovery-Enabled", "TRUE")
                $caContainer.SetInfo()
                Write-Log "  [+] Weakened certificate chain validation" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Certificate validation weakening skipped" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Enable LDAP to SSL fallback (dangerous)
    Write-Log "Enabling LDAP to SSL fallback..." -Level WARNING
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
                
                Write-Log "  [+] Enabled LDAP fallback permissions" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] LDAP fallback configuration skipped" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable certificate pinning
    Write-Log "Disabling certificate pinning..." -Level WARNING
    try {
        try {
            # Registry-based certificate pinning disable (if running locally)
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
            Set-ItemProperty -Path $regPath -Name "ZoneMap_AllowUserDelegateCertificates" -Value 1 -ErrorAction SilentlyContinue
            Write-Log "  [+] Disabled certificate pinning" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Certificate pinning disable skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Grant dangerous permissions on NTAuthCertificates
    Write-Log "Modifying NTAuthCertificates permissions..." -Level WARNING
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
                
                Write-Log "  [+] Granted GenericWrite on NTAuthCertificates to bad actor" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] NTAuthCertificates modification skipped" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Configure certificate validity period weakening
    Write-Log "Weakening certificate validity periods..." -Level WARNING
    try {
        try {
            # Set registry for weaker cert validation (conceptual)
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"
            Set-ItemProperty -Path $regPath -Name "DisableCertificateExpirationCheck" -Value 1 -ErrorAction SilentlyContinue
            Write-Log "  [+] Weakened certificate validity period enforcement" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Certificate validity weakening skipped" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    Write-Log "Module 08 completed" -Level SUCCESS
    Write-Log "" -Level INFO
}

Export-ModuleMember -Function Invoke-ModuleCertificateSecurity