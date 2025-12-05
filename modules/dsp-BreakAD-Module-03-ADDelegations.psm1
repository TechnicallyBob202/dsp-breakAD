function Invoke-ModuleADDelegations {
    <#
    .SYNOPSIS
        AD delegations and security misconfigurations
    
    .PARAMETER Environment
        Hashtable containing domain information
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
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
    
    # BdActrD37: Full Control on Domain NC (all objects and descendant objects)
    Write-Host "Granting Full Control on Domain NC..." -ForegroundColor Yellow
    try {
        $badActor7 = Get-ADUser -Filter { SamAccountName -eq "BdActrD37" } -ErrorAction SilentlyContinue
        if ($badActor7) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor7.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Granted Full Control on Domain NC to BdActrD37" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD38: Full Control on Computer objects (descendants only)
    Write-Host "Granting Full Control on Computer objects..." -ForegroundColor Yellow
    try {
        $badActor8 = Get-ADUser -Filter { SamAccountName -eq "BdActrD38" } -ErrorAction SilentlyContinue
        if ($badActor8) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $computerSchemaGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor8.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"Descendents"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $computerSchemaGUID, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Granted Full Control on Computer objects to BdActrD38" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD39: Read/Write userAccountControl on Computer objects
    Write-Host "Granting Read/Write userAccountControl on Computer objects..." -ForegroundColor Yellow
    try {
        $badActor9 = Get-ADUser -Filter { SamAccountName -eq "BdActrD39" } -ErrorAction SilentlyContinue
        if ($badActor9) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $computerSchemaGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
            $userAccountControlGUID = "bf967a68-0de6-11d0-a285-00aa003049e2"
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor9.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty,WriteProperty"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"Descendents"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $userAccountControlGUID, $aceInheritance, $computerSchemaGUID)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Granted Read/Write userAccountControl to BdActrD39" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD310-D312: Add to protected groups
    Write-Host "Adding accounts to protected groups..." -ForegroundColor Yellow
    try {
        $aoGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $boGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $soGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        
        $groupCount = 0
        
        if ($aoGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD310" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $aoGroup -Members $u -ErrorAction SilentlyContinue
                $groupCount++
            }
        }
        
        if ($boGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD311" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $boGroup -Members $u -ErrorAction SilentlyContinue
                $groupCount++
            }
        }
        
        if ($soGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD312" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $soGroup -Members $u -ErrorAction SilentlyContinue
                $groupCount++
            }
        }
        
        Write-Host "  [+] Added $groupCount accounts to protected groups" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD313-D317: Grant LAPS read permissions on computers
    Write-Host "Granting LAPS read permissions on computers..." -ForegroundColor Yellow
    try {
        $lapsGUID = "8a771fe0-a36b-4788-aca0-e1ee3692bb64"
        $testOU = "OU=TEST,$domainDN"
        $computers = Get-ADComputer -Filter * -SearchBase $testOU -ErrorAction SilentlyContinue
        
        if ($computers) {
            if ($computers -isnot [array]) { $computers = @($computers) }
            
            $lapsCount = 0
            for ($i = 0; $i -lt [Math]::Min(5, $computers.Count); $i++) {
                $badActorNum = 13 + $i
                $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActrD3$badActorNum" } -ErrorAction SilentlyContinue
                if ($badActor) {
                    $computer = [ADSI]("LDAP://$rwdcFQDN/$($computers[$i].DistinguishedName)")
                    $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor.SID)
                    $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty"
                    $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                    $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $lapsGUID, $aceInheritance)
                    $computer.psbase.objectSecurity.AddAccessRule($ace)
                    $computer.psbase.commitchanges()
                    $lapsCount++
                }
            }
            Write-Host "  [+] Granted LAPS read on $lapsCount computers" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD317: Replicate Changes All on Domain NC
    Write-Host "Granting Replicate Changes All on Domain NC..." -ForegroundColor Yellow
    try {
        $badActor17 = Get-ADUser -Filter { SamAccountName -eq "BdActrD317" } -ErrorAction SilentlyContinue
        if ($badActor17) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $replicateChangesAllGUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor17.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $replicateChangesAllGUID, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Granted Replicate Changes All to BdActrD317" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD318: Set Owner on Domain NC
    Write-Host "Setting Domain NC owner..." -ForegroundColor Yellow
    try {
        $badActor18 = Get-ADUser -Filter { SamAccountName -eq "BdActrD318" } -ErrorAction SilentlyContinue
        if ($badActor18) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor18.SID)
            $domainObj.psbase.objectSecurity.SetOwner($badActorSID)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Set BdActrD318 as Domain NC owner" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD319: Write DACL on Domain NC
    Write-Host "Granting Write DACL on Domain NC..." -ForegroundColor Yellow
    try {
        $badActor19 = Get-ADUser -Filter { SamAccountName -eq "BdActrD319" } -ErrorAction SilentlyContinue
        if ($badActor19) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor19.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"WriteDACL"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Granted Write DACL to BdActrD319" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD320: Write Owner on Domain NC
    Write-Host "Granting Write Owner on Domain NC..." -ForegroundColor Yellow
    try {
        $badActor20 = Get-ADUser -Filter { SamAccountName -eq "BdActrD320" } -ErrorAction SilentlyContinue
        if ($badActor20) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor20.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"WriteOwner"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Granted Write Owner to BdActrD320" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD321: Full Control on Domain NC (all)
    Write-Host "Granting Full Control on all Domain NC objects..." -ForegroundColor Yellow
    try {
        $badActor21 = Get-ADUser -Filter { SamAccountName -eq "BdActrD321" } -ErrorAction SilentlyContinue
        if ($badActor21) {
            $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor21.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Granted Full Control to BdActrD321" -ForegroundColor Green
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