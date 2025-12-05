function Invoke-ModuleADDelegations {
    param([Parameter(Mandatory=$true)][hashtable]$Environment)
    
    $domain = $Environment.Domain
    $domainDN = $domain.DistinguishedName
    $domainNetBIOS = $domain.NetBIOSName
    $rwdcFQDN = if ($Environment.DomainController.HostName) { $Environment.DomainController.HostName } else { $domain.PDCEmulator }
    
    $successCount = 0
    $errorCount = 0
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 03: AD Delegations" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # BdActr7: Full Control on Domain NC (all objects and descendant objects)
    Write-Host "Granting Full Control on Domain NC..." -ForegroundColor Yellow
    try {
        $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`7" } -ErrorAction SilentlyContinue
        if ($badActor) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Full Control on Domain NC" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr8: Full Control on Computer objects (descendants only)
    Write-Host "Granting Full Control on Computer objects..." -ForegroundColor Yellow
    try {
        $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`8" } -ErrorAction SilentlyContinue
        if ($badActor) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $computerSchemaGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"Descendents"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $computerSchemaGUID, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Full Control on Computer objects" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr9: Read/Write userAccountControl on Computer objects
    Write-Host "Granting Read/Write userAccountControl on Computer objects..." -ForegroundColor Yellow
    try {
        $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`9" } -ErrorAction SilentlyContinue
        if ($badActor) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $computerSchemaGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
            $userAccountControlGUID = "bf967a68-0de6-11d0-a285-00aa003049e2"
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty,WriteProperty"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"Descendents"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $userAccountControlGUID, $aceInheritance, $computerSchemaGUID)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Read/Write userAccountControl on Computer objects" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr10, 11, 12: Add to protected groups
    Write-Host "Adding accounts to protected groups..." -ForegroundColor Yellow
    try {
        $aoGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $boGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $soGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        
        if ($aoGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`10" } -ErrorAction SilentlyContinue
            if ($u) { Add-ADGroupMember -Identity $aoGroup -Members $u -ErrorAction SilentlyContinue }
        }
        
        if ($boGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`11" } -ErrorAction SilentlyContinue
            if ($u) { Add-ADGroupMember -Identity $boGroup -Members $u -ErrorAction SilentlyContinue }
        }
        
        if ($soGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`12" } -ErrorAction SilentlyContinue
            if ($u) { Add-ADGroupMember -Identity $soGroup -Members $u -ErrorAction SilentlyContinue }
        }
        
        Write-Host "  [+] Added 3 accounts to protected groups" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr17: Replicate Changes All on Domain NC
    Write-Host "Granting Replicate Changes All on Domain NC..." -ForegroundColor Yellow
    try {
        $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`17" } -ErrorAction SilentlyContinue
        if ($badActor) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $replicateChangesAllGUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $replicateChangesAllGUID, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Replicate Changes All on Domain NC" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr18: Set Owner on Domain NC
    Write-Host "Setting Domain NC owner..." -ForegroundColor Yellow
    try {
        $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`18" } -ErrorAction SilentlyContinue
        if ($badActor) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
            $domainObj.psbase.objectSecurity.SetOwner($badActorSID)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Set as Domain NC owner" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr19: Write DACL on Domain NC
    Write-Host "Granting Write DACL on Domain NC..." -ForegroundColor Yellow
    try {
        $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`19" } -ErrorAction SilentlyContinue
        if ($badActor) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"WriteDACL"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Write DACL on Domain NC" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr20: Write Owner on Domain NC
    Write-Host "Granting Write Owner on Domain NC..." -ForegroundColor Yellow
    try {
        $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`20" } -ErrorAction SilentlyContinue
        if ($badActor) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"WriteOwner"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Write Owner on Domain NC" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr21: Full Control on Domain NC (all)
    Write-Host "Granting Full Control on all Domain NC objects..." -ForegroundColor Yellow
    try {
        $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`21" } -ErrorAction SilentlyContinue
        if ($badActor) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Full Control on all Domain NC objects" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    Write-Host "Module 03 completed" -ForegroundColor Green
    Write-Host ""
    
    if ($errorCount -gt $successCount) { return $false }
    return $true
}

Export-ModuleMember -Function Invoke-ModuleADDelegations