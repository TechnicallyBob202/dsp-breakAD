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
    $rwdcFQDN = $Environment.DomainController.HostName
    
    Write-Log "" -Level INFO
    Write-Log "=== MODULE 05: Infrastructure Security ===" -Level INFO
    Write-Log "" -Level INFO
    
    # Modify DC computer account userAccountControl
    Write-Log "Modifying DC computer account settings..." -Level WARNING
    try {
        $dcComputer = Get-ADComputer -Filter { DNSHostName -eq $rwdcFQDN } -ErrorAction SilentlyContinue
        if ($dcComputer) {
            try {
                # Remove trusted for delegation flag and other protective flags
                $uac = $dcComputer.UserAccountControl
                $uac = $uac -band -bnot 0x100000  # Remove TRUSTED_FOR_DELEGATION
                $uac = $uac -band -bnot 0x80000   # Remove NOT_DELEGATED
                Set-ADComputer -Identity $dcComputer -Replace @{"userAccountControl" = $uac}
                Write-Log "  [+] Modified DC computer account flags" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error modifying DC account: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Configure dangerous delegation on DC
    Write-Log "Configuring delegation on DC computer..." -Level WARNING
    try {
        $dcComputer = Get-ADComputer -Filter { DNSHostName -eq $rwdcFQDN } -ErrorAction SilentlyContinue
        if ($dcComputer) {
            try {
                # Enable unconstrained delegation (dangerous for DC)
                Set-ADComputer -Identity $dcComputer -TrustedForDelegation $true
                Write-Log "  [+] Enabled unconstrained delegation on DC" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Modify schema admins and enterprise admins
    Write-Log "Modifying schema and enterprise admin groups..." -Level WARNING
    try {
        $badActor100 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`100" } -ErrorAction SilentlyContinue
        $badActor101 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`101" } -ErrorAction SilentlyContinue
        
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
        
        Write-Log "  [+] Added bad actors to forest-level groups: $addedCount" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Configure dangerous replication settings
    Write-Log "Configuring dangerous replication settings..." -Level WARNING
    try {
        # Find a bad actor to assign dangerous perms
        $badActor102 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`102" } -ErrorAction SilentlyContinue
        
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
                
                Write-Log "  [+] Granted dangerous replication rights to bad actor" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error setting replication rights: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Configure DomainDNSZones permissions
    Write-Log "Configuring DomainDNSZones permissions..." -Level WARNING
    try {
        $badActor103 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`103" } -ErrorAction SilentlyContinue
        
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
                
                Write-Log "  [+] Granted Full Control on DomainDnsZones" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error setting DNS zone permissions: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Modify schema permissions
    Write-Log "Modifying schema permissions..." -Level WARNING
    try {
        $badActor104 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`104" } -ErrorAction SilentlyContinue
        
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
                    
                    Write-Log "  [+] Granted Full Control on Schema" -Level SUCCESS
                }
            }
            catch {
                Write-Log "  [!] Error setting schema permissions: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Modify configuration partition permissions
    Write-Log "Modifying configuration partition permissions..." -Level WARNING
    try {
        $badActor105 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`105" } -ErrorAction SilentlyContinue
        
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
                
                Write-Log "  [+] Granted Full Control on Configuration" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error setting config permissions: $_" -Level WARNING
            }
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Set DC to allow anonymous access
    Write-Log "Configuring anonymous access settings..." -Level WARNING
    try {
        # Modify anonymousAccessPolicy registry setting
        try {
            # Note: This requires registry access on the DC
            # In lab scenarios, might need explicit credential passing
            Write-Log "  [!] Anonymous access modification requires DC registry access - skipped" -Level WARNING
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Disable LDAP signing requirement
    Write-Log "Configuring LDAP signing settings..." -Level WARNING
    try {
        # Modify domain policy for LDAP signing
        try {
            # Note: This requires Group Policy or registry modification
            # Usually requires: Set-GPRegistryValue or direct registry edit
            Write-Log "  [!] LDAP signing modification requires DC registry/GPO access - skipped" -Level WARNING
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Enable null session pipes
    Write-Log "Configuring null session settings..." -Level WARNING
    try {
        # Note: Null session access typically requires registry modifications
        Write-Log "  [!] Null session configuration requires DC registry access - skipped" -Level WARNING
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    Write-Log "Module 05 completed" -Level SUCCESS
    Write-Log "" -Level INFO
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity