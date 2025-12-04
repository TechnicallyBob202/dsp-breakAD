################################################################################
##
## dsp-BreakAD-Module-03-ADDelegations.psm1
##
## Creates various Active Directory delegations and security misconfigurations
## 
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Invoke-ModuleADDelegations {
    <#
    .SYNOPSIS
        Creates AD delegations and security misconfigurations
    
    .DESCRIPTION
        Configures various dangerous delegations and security issues:
        - Enable inheritance on AdminSDHolder
        - Add non-admin user with Full Control on AdminSDHolder
        - Modify user display specifiers
        - Update default permissions on User ObjectClass
        - Set non-admin as owner of DC computer account
        - Add Enterprise Key Admins to Domain NC
        - Grant gMSA password read access to non-admin users
        - Enable built-in Guest account
        - Set permissions for SERVER_TRUST_ACCOUNT
        - Disable security flags on LAPS attribute
        - Add non-admin accounts to protected groups
        - Grant LAPS read and computer permissions
        - Grant Domain NC replication and ownership rights
        - Configure Machine Account Quota
    
    .PARAMETER Environment
        Hashtable containing domain information from preflight checks
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domainDN = $Environment.Domain.DistinguishedName
    $domainNetBIOS = $Environment.Domain.NetBIOSName
    $rwdcFQDN = $Environment.DomainController.HostName
    
    $forest = Get-ADForest -Current LocalComputer
    $forestSchemaFsmoFQDN = $forest.SchemaMaster
    $forestDnmFsmoFQDN = $forest.DomainNamingMaster
    $forestConfigNCDN = $forest.PartitionsContainer.Replace("CN=Partitions,","")
    $forestSchemaNCDN = "CN=Schema," + $forestConfigNCDN
    
    $dcContainerDN = "CN=Domain Controllers,$domainDN"
    $testOU = "OU=TEST,$domainDN"
    
    Write-Host "Configuring AD delegations and security misconfigurations..." -ForegroundColor Cyan
    Write-Host ""
    
    # Enable Inheritance on AdminSDHolder
    Write-Host "Enabling inheritance on AdminSDHolder..." -ForegroundColor Yellow
    try {
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
        $adminSDHolder = [ADSI]("LDAP://$rwdcFQDN/$adminSDHolderDN")
        $dacl = $adminSDHolder.psbase.objectSecurity
        
        if ($dacl.get_AreAccessRulesProtected()) {
            $dacl.SetAccessRuleProtection($false, $true)  # Disable protection, preserve inherited ACEs
            $adminSDHolder.psbase.commitchanges()
            Write-Host "  [+] Inheritance enabled on AdminSDHolder" -ForegroundColor Green
        } else {
            Write-Host "  [!] Inheritance already enabled" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [X] Failed to enable inheritance: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Add non-admin to AdminSDHolder with Full Control
    Write-Host "Adding non-admin user to AdminSDHolder with Full Control..." -ForegroundColor Yellow
    try {
        $badActor0 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`0" } -ErrorAction SilentlyContinue
        if ($badActor0) {
            $adminSDHolder = [ADSI]("LDAP://$rwdcFQDN/$adminSDHolderDN")
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor0.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            
            $adminSDHolder.psbase.objectSecurity.AddAccessRule($ace)
            $adminSDHolder.psbase.commitchanges()
            Write-Host "  [+] Assigned Full Control on AdminSDHolder to BdActr$domainNetBIOS`0" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [X] Failed to add permissions to AdminSDHolder: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Update Display Specifiers
    Write-Host "Modifying display specifiers..." -ForegroundColor Yellow
    try {
        foreach ($lcidCode in @("401", "409", "816")) {
            $displaySpecifierDN = "CN=user-Display,CN=$lcidCode,CN=DisplaySpecifiers,$forestConfigNCDN"
            $displaySpecifier = [ADSI]("LDAP://$forestDnmFsmoFQDN/$displaySpecifierDN")
            $randomNum = Get-Random -Minimum 1 -Maximum 99
            $newContextMenu = "$randomNum,Bad Action,C:\TEMP\BadCode.cmd"
            
            # Use PutEx to append to adminContextMenu
            [int]$ADS_PROPERTY_APPEND = 3
            $displaySpecifier.PutEx($ADS_PROPERTY_APPEND, "adminContextMenu", @($newContextMenu))
            $displaySpecifier.SetInfo()
            Write-Host "  [+] Added context menu entry to display specifier CN=$lcidCode" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [X] Failed to modify display specifiers: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Update default permissions on User ObjectClass
    Write-Host "Updating default permissions on User ObjectClass..." -ForegroundColor Yellow
    try {
        $userObjectDN = "CN=User,$forestSchemaNCDN"
        $userObject = [ADSI]("LDAP://$forestSchemaFsmoFQDN/$userObjectDN")
        $currentDefaultSD = $userObject.defaultSecurityDescriptor
        
        # Add Everyone with Full Control
        if ($currentDefaultSD -notmatch "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;WD)") {
            $newDefaultSD = "$currentDefaultSD(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;WD)"
            $userObject.Put("defaultSecurityDescriptor", $newDefaultSD)
            $userObject.SetInfo()
            Write-Host "  [+] Added Everyone with Full Control to User ObjectClass default permissions" -ForegroundColor Green
        } else {
            Write-Host "  [!] ACE already present" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [X] Failed to update default permissions: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Set non-admin as owner of DC computer account
    Write-Host "Setting non-admin as owner of DC computer account..." -ForegroundColor Yellow
    try {
        $dcAccounts = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -SearchBase $dcContainerDN -ErrorAction SilentlyContinue
        if ($dcAccounts.Count -gt 0) {
            $randomDC = Get-Random -InputObject $dcAccounts
            $badActor1 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`1" } -ErrorAction SilentlyContinue
            
            if ($badActor1) {
                $dcObj = [ADSI]("LDAP://$rwdcFQDN/$($randomDC.DistinguishedName)")
                $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor1.SID)
                $dcObj.psbase.objectSecurity.SetOwner($badActorSID)
                $dcObj.psbase.commitchanges()
                Write-Host "  [+] Set BdActr$domainNetBIOS`1 as owner of $($randomDC.Name)" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "  [X] Failed to set DC owner: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Enable built-in Guest account
    Write-Host "Enabling built-in Guest account..." -ForegroundColor Yellow
    try {
        $guestSID = "$domainSID-501"
        $guestAccount = Get-ADUser -Filter { SID -eq $guestSID } -ErrorAction SilentlyContinue
        if ($guestAccount) {
            Set-ADUser -Identity $guestAccount -Enabled $true
            Write-Host "  [+] Enabled built-in Guest account" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [X] Failed to enable Guest account: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Set permissions for SERVER_TRUST_ACCOUNT on Domain NC
    Write-Host "Setting permissions for SERVER_TRUST_ACCOUNT..." -ForegroundColor Yellow
    try {
        $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
        
        # Full Control for all objects
        $badActor7 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`7" } -ErrorAction SilentlyContinue
        if ($badActor7) {
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor7.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Assigned Full Control on Domain NC to BdActr$domainNetBIOS`7" -ForegroundColor Green
        }
        
        # Full Control for Computer objects only
        $badActor8 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`8" } -ErrorAction SilentlyContinue
        if ($badActor8) {
            $computerSchemaGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"  # Computer ObjectClass
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor8.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"Descendents"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance, $computerSchemaGUID)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Assigned Full Control on Computer objects to BdActr$domainNetBIOS`8" -ForegroundColor Green
        }
        
        # Read/Write userAccountControl on Computer objects
        $badActor9 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`9" } -ErrorAction SilentlyContinue
        if ($badActor9) {
            $computerSchemaGUID = "bf967a86-0de6-11d0-a285-00aa003049e2"  # Computer ObjectClass
            $userAccountControlGUID = "bf967a68-0de6-11d0-a285-00aa003049e2"  # userAccountControl attribute
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor9.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty","WriteProperty"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"Descendents"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $userAccountControlGUID, $aceInheritance, $computerSchemaGUID)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            $domainObj.psbase.commitchanges()
            Write-Host "  [+] Assigned Read/Write userAccountControl on Computer objects to BdActr$domainNetBIOS`9" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [X] Failed to set SERVER_TRUST_ACCOUNT permissions: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Disable security flags on LAPS attribute (ms-Mcs-AdmPwd)
    Write-Host "Disabling security flags on LAPS attribute..." -ForegroundColor Yellow
    try {
        $lapsAttrDN = "CN=ms-Mcs-AdmPwd,$forestSchemaNCDN"
        $lapsAttr = [ADSI]("LDAP://$forestSchemaFsmoFQDN/$lapsAttrDN")
        $currentSearchFlags = $lapsAttr.searchFlags[0]
        
        # Disable CONFIDENTIAL (128), NEVER_AUDIT_VALUE (256), RODC_FILTERED (512)
        $newSearchFlags = $currentSearchFlags -bxor 128 -bxor 256 -bxor 512
        $lapsAttr.Put("searchFlags", $newSearchFlags)
        $lapsAttr.SetInfo()
        Write-Host "  [+] Disabled security flags (CONFIDENTIAL, NEVER_AUDIT_VALUE, RODC_FILTERED) on ms-Mcs-AdmPwd" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] LAPS not installed or failed: $_" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Add non-admin accounts to protected groups
    Write-Host "Adding non-admin accounts to protected groups..." -ForegroundColor Yellow
    try {
        # Account Operators
        $badActor10 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`10" } -ErrorAction SilentlyContinue
        if ($badActor10) {
            $accountOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
            if ($accountOpsGroup) {
                Add-ADGroupMember -Identity $accountOpsGroup -Members $badActor10 -ErrorAction SilentlyContinue
                Write-Host "  [+] Added BdActr$domainNetBIOS`10 to Account Operators" -ForegroundColor Green
            }
        }
        
        # Backup Operators
        $badActor11 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`11" } -ErrorAction SilentlyContinue
        if ($badActor11) {
            $backupOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
            if ($backupOpsGroup) {
                Add-ADGroupMember -Identity $backupOpsGroup -Members $badActor11 -ErrorAction SilentlyContinue
                Write-Host "  [+] Added BdActr$domainNetBIOS`11 to Backup Operators" -ForegroundColor Green
            }
        }
        
        # Server Operators
        $badActor12 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`12" } -ErrorAction SilentlyContinue
        if ($badActor12) {
            $serverOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
            if ($serverOpsGroup) {
                Add-ADGroupMember -Identity $serverOpsGroup -Members $badActor12 -ErrorAction SilentlyContinue
                Write-Host "  [+] Added BdActr$domainNetBIOS`12 to Server Operators" -ForegroundColor Green
            }
        }
        
        # Domain Admins
        $badActor22 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`22" } -ErrorAction SilentlyContinue
        if ($badActor22) {
            $domainAdminsGroup = Get-ADGroup -Filter { SamAccountName -eq "Domain Admins" } -ErrorAction SilentlyContinue
            if ($domainAdminsGroup) {
                Add-ADGroupMember -Identity $domainAdminsGroup -Members $badActor22 -ErrorAction SilentlyContinue
                Write-Host "  [+] Added BdActr$domainNetBIOS`22 to Domain Admins" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "  [X] Failed to add members to protected groups: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Grant LAPS and computer permissions
    Write-Host "Granting LAPS and computer permissions..." -ForegroundColor Yellow
    try {
        $computers = Get-ADComputer -Filter * -SearchBase $testOU -ErrorAction SilentlyContinue
        if ($computers.Count -gt 0) {
            foreach ($computer in $computers) {
                $computerObj = [ADSI]("LDAP://$rwdcFQDN/$($computer.DistinguishedName)")
                
                # Read LAPS
                $badActor13 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`13" } -ErrorAction SilentlyContinue
                if ($badActor13) {
                    $lapsGUID = "8a771fe0-a36b-4788-aca0-e1ee3692bb64"
                    $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor13.SID)
                    $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty"
                    $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                    $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $lapsGUID, $aceInheritance)
                    $computerObj.psbase.objectSecurity.AddAccessRule($ace)
                }
                
                # Set Owner
                $badActor14 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`14" } -ErrorAction SilentlyContinue
                if ($badActor14) {
                    $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor14.SID)
                    $computerObj.psbase.objectSecurity.SetOwner($badActorSID)
                }
                
                # Write DACL
                $badActor15 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`15" } -ErrorAction SilentlyContinue
                if ($badActor15) {
                    $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor15.SID)
                    $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"WriteDACL"
                    $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
                    $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
                    $computerObj.psbase.objectSecurity.AddAccessRule($ace)
                }
                
                $computerObj.psbase.commitchanges()
            }
            Write-Host "  [+] Granted LAPS and computer permissions on TEST OU computers" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [X] Failed to grant computer permissions: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Grant Domain NC replication and ownership rights
    Write-Host "Granting Domain NC replication and ownership rights..." -ForegroundColor Yellow
    try {
        $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
        
        # Replicate Changes All
        $badActor17 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`17" } -ErrorAction SilentlyContinue
        if ($badActor17) {
            $replicateChangesAllGUID = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor17.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $replicateChangesAllGUID, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            Write-Host "  [+] Granted Replicate Changes All to BdActr$domainNetBIOS`17" -ForegroundColor Green
        }
        
        # Set Owner
        $badActor18 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`18" } -ErrorAction SilentlyContinue
        if ($badActor18) {
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor18.SID)
            $domainObj.psbase.objectSecurity.SetOwner($badActorSID)
            Write-Host "  [+] Set BdActr$domainNetBIOS`18 as owner of Domain NC" -ForegroundColor Green
        }
        
        # Write DACL
        $badActor19 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`19" } -ErrorAction SilentlyContinue
        if ($badActor19) {
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor19.SID)
            $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"WriteDACL"
            $aceType = [System.Security.AccessControl.AccessControlType]"Allow"
            $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($badActorSID, $aceRight, $aceType, $aceInheritance)
            $domainObj.psbase.objectSecurity.AddAccessRule($ace)
            Write-Host "  [+] Granted WriteDACL to BdActr$domainNetBIOS`19" -ForegroundColor Green
        }
        
        $domainObj.psbase.commitchanges()
    }
    catch {
        Write-Host "  [X] Failed to grant Domain NC rights: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    # Configure Machine Account Quota
    Write-Host "Configuring Machine Account Quota..." -ForegroundColor Yellow
    try {
        $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
        $newQuota = Get-Random -Minimum 1 -Maximum 25
        $domainObj.Put("ms-DS-MachineAccountQuota", $newQuota)
        $domainObj.SetInfo()
        Write-Host "  [+] Set Machine Account Quota to $newQuota" -ForegroundColor Green
    }
    catch {
        Write-Host "  [X] Failed to configure Machine Account Quota: $_" -ForegroundColor Red
    }
    Write-Host ""
    
    Write-Host "AD delegations and security misconfigurations completed" -ForegroundColor Cyan
    Write-Host ""
}

Export-ModuleMember -Function Invoke-ModuleADDelegations