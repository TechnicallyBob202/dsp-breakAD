################################################################################
##
## dsp-BreakAD-Module-05-InfrastructureSecurity.psm1
##
## Configures infrastructure with security misconfigurations
## 
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Invoke-ModuleInfrastructureSecurity {
    <#
    .SYNOPSIS
        Configures infrastructure security misconfigurations
    
    .DESCRIPTION
        Applies security misconfigurations at infrastructure level:
        - Modify DC computer account settings
        - Configure dangerous delegation on DC
        - Set weak site replication settings
        - Configure DNS admin delegation
        - Enable unauthenticated access on shares
        - Modify schema admins and enterprise admins
        - Set risky replication settings
        - Configure insecure LDAP bindings
        - Modify DomainDNSZones permissions
        - Configure forest-level misconfigurations
    
    .PARAMETER Environment
        Hashtable with Domain, DomainController, etc.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domainDN = $Environment.Domain.DistinguishedName
    $domainNetBIOS = $Environment.Domain.NetBIOSName
    $rwdcFQDN = if ($Environment.DomainController.HostName) { $Environment.DomainController.HostName } else { $Environment.Domain.PDCEmulator }
    
    Write-Host "" -ForegroundColor Cyan
    Write-Host "=== MODULE 05: Infrastructure Security ===" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    
    # Modify DC computer account userAccountControl
    Write-Host "Modifying DC computer account settings..." -ForegroundColor Yellow
    try {
        $dcComputer = Get-ADComputer -Filter { DNSHostName -eq $rwdcFQDN } -ErrorAction SilentlyContinue
        if ($dcComputer) {
            try {
                # Remove trusted for delegation flag and other protective flags
                $uac = $dcComputer.UserAccountControl
                $uac = $uac -band -bnot 0x100000  # Remove TRUSTED_FOR_DELEGATION
                $uac = $uac -band -bnot 0x80000   # Remove NOT_DELEGATED
                Set-ADComputer -Identity $dcComputer -Replace @{"userAccountControl" = $uac}
                Write-Host "  [+] Modified DC computer account flags" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error modifying DC account: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Configure dangerous delegation on DC
    Write-Host "Configuring delegation on DC computer..." -ForegroundColor Yellow
    try {
        $dcComputer = Get-ADComputer -Filter { DNSHostName -eq $rwdcFQDN } -ErrorAction SilentlyContinue
        if ($dcComputer) {
            try {
                # Enable unconstrained delegation (dangerous for DC)
                Set-ADComputer -Identity $dcComputer -TrustedForDelegation $true
                Write-Host "  [+] Enabled unconstrained delegation on DC" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Modify schema admins and enterprise admins
    Write-Host "Modifying schema and enterprise admin groups..." -ForegroundColor Yellow
    try {
        $badActor100 = $badActorName100 = "BdActr$domainNetBIOS" + "100"; Get-ADUser -Filter { SamAccountName -eq $badActorName100 } -ErrorAction SilentlyContinue
        $badActor101 = $badActorName101 = "BdActr$domainNetBIOS" + "101"; Get-ADUser -Filter { SamAccountName -eq $badActorName101 } -ErrorAction SilentlyContinue
        
        $schemaAdmins = Get-ADGroup -Filter { Name -eq "Schema Admins" } -ErrorAction SilentlyContinue
        $enterpriseAdmins = Get-ADGroup -Filter { Name -eq "Enterprise Admins" } -ErrorAction SilentlyContinue
        
        $addedCount = 0
        
        if ($schemaAdmins -and $badActor100) {
            try {
                Add-ADGroupMember -Identity $schemaAdmins -Members $badActor100 -ErrorAction SilentlyContinue
                $addedCount++
            }
            catch { }
        }
        
        if ($enterpriseAdmins -and $badActor101) {
            try {
                Add-ADGroupMember -Identity $enterpriseAdmins -Members $badActor101 -ErrorAction SilentlyContinue
                $addedCount++
            }
            catch { }
        }
        
        Write-Host "  [+] Added bad actors to forest-level groups: $addedCount" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Configure dangerous replication settings
    Write-Host "Configuring dangerous replication settings..." -ForegroundColor Yellow
    try {
        # Find a bad actor to assign dangerous perms
        $badActor102 = $badActorName102 = "BdActr$domainNetBIOS" + "102"; Get-ADUser -Filter { SamAccountName -eq $badActorName102 } -ErrorAction SilentlyContinue
        
        if ($badActor102) {
            try {
                $dcObj = [ADSI]("LDAP://$rwdcFQDN/CN=NTDS Settings,CN=$($Environment.DomainController.Name),CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,$domainDN")
                
                # Grant replication rights to bad actor
                $replicateChangesGUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
                $badActorSecurityId = New-Object System.Security.Principal.SecurityIdentifier($badActor102.SID)
                
                $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"
                $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
                
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSecurityId, $aceRight, $aceType, [guid]$replicateChangesGUID, $aceInheritance)
                $dcObj.psbase.objectSecurity.AddAccessRule($ace)
                $dcObj.psbase.commitchanges()
                
                Write-Host "  [+] Granted dangerous replication rights to bad actor" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error setting replication rights: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Configure DomainDNSZones permissions
    Write-Host "Configuring DomainDNSZones permissions..." -ForegroundColor Yellow
    try {
        $badActor103 = $badActorName103 = "BdActr$domainNetBIOS" + "103"; Get-ADUser -Filter { SamAccountName -eq $badActorName103 } -ErrorAction SilentlyContinue
        
        if ($badActor103) {
            try {
                $dnsZoneDN = "DC=DomainDnsZones,$domainDN"
                $dnsZoneObj = [ADSI]("LDAP://$rwdcFQDN/$dnsZoneDN")
                
                # Add bad actor with full control
                $badActorSecurityId = New-Object System.Security.Principal.SecurityIdentifier($badActor103.SID)
                $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
                $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
                
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSecurityId, $aceRight, $aceType, $aceInheritance)
                $dnsZoneObj.psbase.objectSecurity.AddAccessRule($ace)
                $dnsZoneObj.psbase.commitchanges()
                
                Write-Host "  [+] Granted Full Control on DomainDnsZones" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error setting DNS zone permissions: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Modify schema permissions
    Write-Host "Modifying schema permissions..." -ForegroundColor Yellow
    try {
        $badActor104 = $badActorName104 = "BdActr$domainNetBIOS" + "104"; Get-ADUser -Filter { SamAccountName -eq $badActorName104 } -ErrorAction SilentlyContinue
        
        if ($badActor104) {
            try {
                $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                $schemaDN = $forest.SchemaRoleOwner.Partitions | Where-Object { $_ -match "^CN=Schema" }
                
                if ($schemaDN) {
                    $schemaObj = [ADSI]("LDAP://$rwdcFQDN/$schemaDN")
                    $badActorSecurityId = New-Object System.Security.Principal.SecurityIdentifier($badActor104.SID)
                    
                    $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
                    $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                    $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
                    
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSecurityId, $aceRight, $aceType, $aceInheritance)
                    $schemaObj.psbase.objectSecurity.AddAccessRule($ace)
                    $schemaObj.psbase.commitchanges()
                    
                    Write-Host "  [+] Granted Full Control on Schema" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "  [!] Error setting schema permissions: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Modify configuration partition permissions
    Write-Host "Modifying configuration partition permissions..." -ForegroundColor Yellow
    try {
        $badActor105 = $badActorName105 = "BdActr$domainNetBIOS" + "105"; Get-ADUser -Filter { SamAccountName -eq $badActorName105 } -ErrorAction SilentlyContinue
        
        if ($badActor105) {
            try {
                $configDN = "CN=Configuration,$domainDN"
                $configObj = [ADSI]("LDAP://$rwdcFQDN/$configDN")
                $badActorSecurityId = New-Object System.Security.Principal.SecurityIdentifier($badActor105.SID)
                
                $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
                $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
                
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSecurityId, $aceRight, $aceType, $aceInheritance)
                $configObj.psbase.objectSecurity.AddAccessRule($ace)
                $configObj.psbase.commitchanges()
                
                Write-Host "  [+] Granted Full Control on Configuration" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error setting config permissions: $_" -ForegroundColor Yellow
            }
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Set DC to allow anonymous access
    Write-Host "Configuring anonymous access settings..." -ForegroundColor Yellow
    try {
        # Modify anonymousAccessPolicy registry setting
        try {
            # Note: This requires registry access on the DC
            # In lab scenarios, might need explicit credential passing
            Write-Host "  [!] Anonymous access modification requires DC registry access - skipped" -ForegroundColor Yellow
        }
        catch {
            Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Disable LDAP signing requirement
    Write-Host "Configuring LDAP signing settings..." -ForegroundColor Yellow
    try {
        # Modify domain policy for LDAP signing
        try {
            # Note: This requires Group Policy or registry modification
            # Usually requires: Set-GPRegistryValue or direct registry edit
            Write-Host "  [!] LDAP signing modification requires DC registry/GPO access - skipped" -ForegroundColor Yellow
        }
        catch {
            Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    # Enable null session pipes
    Write-Host "Configuring null session settings..." -ForegroundColor Yellow
    try {
        # Note: Null session access typically requires registry modifications
        Write-Host "  [!] Null session configuration requires DC registry access - skipped" -ForegroundColor Yellow
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    
    Write-Host "Module 05 completed" -ForegroundColor Green
    Write-Host "" -ForegroundColor Cyan
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity