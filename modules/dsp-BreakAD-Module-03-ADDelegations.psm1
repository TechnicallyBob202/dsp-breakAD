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
    
    Write-Log "Configuring AD delegations and security misconfigurations..." -Level INFO
    Write-Log "" -Level INFO
    
    # Enable Inheritance on AdminSDHolder
    Write-Log "Enabling inheritance on AdminSDHolder..." -Level WARNING
    try {
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
        $adminSDHolder = [ADSI]("LDAP://$rwdcFQDN/$adminSDHolderDN")
        $dacl = $adminSDHolder.psbase.objectSecurity
        
        if ($dacl.get_AreAccessRulesProtected()) {
            $dacl.SetAccessRuleProtection($false, $true)  # Disable protection, preserve inherited ACEs
            $adminSDHolder.psbase.commitchanges()
            Write-Log "  [+] Inheritance enabled on AdminSDHolder" -Level SUCCESS
        } else {
            Write-Log "  [!] Inheritance already enabled" -Level WARNING
        }
    }
    catch {
        Write-Log "  [X] Failed to enable inheritance: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Add non-admin to AdminSDHolder with Full Control
    Write-Log "Adding non-admin user to AdminSDHolder with Full Control..." -Level WARNING
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
            Write-Log "  [+] Assigned Full Control on AdminSDHolder to BdActr$domainNetBIOS`0" -Level SUCCESS
        }
    }
    catch {
        Write-Log "  [X] Failed to add permissions to AdminSDHolder: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Update Display Specifiers
    Write-Log "Modifying display specifiers..." -Level WARNING
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
            Write-Log "  [+] Added context menu entry to display specifier CN=$lcidCode" -Level SUCCESS
        }
    }
    catch {
        Write-Log "  [X] Failed to modify display specifiers: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Update default permissions on User ObjectClass
    Write-Log "Updating default permissions on User ObjectClass..." -Level WARNING
    try {
        $userObjectDN = "CN=User,$forestSchemaNCDN"
        $userObject = [ADSI]("LDAP://$forestSchemaFsmoFQDN/$userObjectDN")
        $currentDefaultSD = $userObject.defaultSecurityDescriptor
        
        # Add Everyone with Full Control
        if ($currentDefaultSD -notmatch "(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;WD)") {
            $newDefaultSD = "$currentDefaultSD(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;WD)"
            $userObject.Put("defaultSecurityDescriptor", $newDefaultSD)
            $userObject.SetInfo()
            Write-Log "  [+] Added Everyone with Full Control to User ObjectClass default permissions" -Level SUCCESS
        } else {
            Write-Log "  [!] ACE already present" -Level WARNING
        }
    }
    catch {
        Write-Log "  [X] Failed to update default permissions: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Set non-admin as owner of DC computer account
    Write-Log "Setting non-admin as owner of DC computer account..." -Level WARNING
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
                Write-Log "  [+] Set BdActr$domainNetBIOS`1 as owner of $($randomDC.Name)" -Level SUCCESS
            }
        }
    }
    catch {
        Write-Log "  [X] Failed to set DC owner: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Enable built-in Guest account
    Write-Log "Enabling built-in Guest account..." -Level WARNING
    try {
        $guestSID = "$domainSID-501"
        $guestAccount = Get-ADUser -Filter { SID -eq $guestSID } -ErrorAction SilentlyContinue
        if ($guestAccount) {
            Set-ADUser -Identity $guestAccount -Enabled $true
            Write-Log "  [+] Enabled built-in Guest account" -Level SUCCESS
        }
    }
    catch {
        Write-Log "  [X] Failed to enable Guest account: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Set permissions for SERVER_TRUST_ACCOUNT on Domain NC
    Write-Log "Setting permissions for SERVER_TRUST_ACCOUNT..." -Level WARNING
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
            Write-Log "  [+] Assigned Full Control on Domain NC to BdActr$domainNetBIOS`7" -Level SUCCESS
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
            Write-Log "  [+] Assigned Full Control on Computer objects to BdActr$domainNetBIOS`8" -Level SUCCESS
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
            Write-Log "  [+] Assigned Read/Write userAccountControl on Computer objects to BdActr$domainNetBIOS`9" -Level SUCCESS
        }
    }
    catch {
        Write-Log "  [X] Failed to set SERVER_TRUST_ACCOUNT permissions: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Disable security flags on LAPS attribute (ms-Mcs-AdmPwd)
    Write-Log "Disabling security flags on LAPS attribute..." -Level WARNING
    try {
        $lapsAttrDN = "CN=ms-Mcs-AdmPwd,$forestSchemaNCDN"
        $lapsAttr = [ADSI]("LDAP://$forestSchemaFsmoFQDN/$lapsAttrDN")
        $currentSearchFlags = $lapsAttr.searchFlags[0]
        
        # Disable CONFIDENTIAL (128), NEVER_AUDIT_VALUE (256), RODC_FILTERED (512)
        $newSearchFlags = $currentSearchFlags -bxor 128 -bxor 256 -bxor 512
        $lapsAttr.Put("searchFlags", $newSearchFlags)
        $lapsAttr.SetInfo()
        Write-Log "  [+] Disabled security flags (CONFIDENTIAL, NEVER_AUDIT_VALUE, RODC_FILTERED) on ms-Mcs-AdmPwd" -Level SUCCESS
    }
    catch {
        Write-Log "  [!] LAPS not installed or failed: $_" -Level WARNING
    }
    Write-Log "" -Level INFO
    
    # Add non-admin accounts to protected groups
    Write-Log "Adding non-admin accounts to protected groups..." -Level WARNING
    try {
        # Account Operators
        $badActor10 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`10" } -ErrorAction SilentlyContinue
        if ($badActor10) {
            $accountOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
            if ($accountOpsGroup) {
                Add-ADGroupMember -Identity $accountOpsGroup -Members $badActor10 -ErrorAction SilentlyContinue
                Write-Log "  [+] Added BdActr$domainNetBIOS`10 to Account Operators" -Level SUCCESS
            }
        }
        
        # Backup Operators
        $badActor11 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`11" } -ErrorAction SilentlyContinue
        if ($badActor11) {
            $backupOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
            if ($backupOpsGroup) {
                Add-ADGroupMember -Identity $backupOpsGroup -Members $badActor11 -ErrorAction SilentlyContinue
                Write-Log "  [+] Added BdActr$domainNetBIOS`11 to Backup Operators" -Level SUCCESS
            }
        }
        
        # Server Operators
        $badActor12 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`12" } -ErrorAction SilentlyContinue
        if ($badActor12) {
            $serverOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
            if ($serverOpsGroup) {
                Add-ADGroupMember -Identity $serverOpsGroup -Members $badActor12 -ErrorAction SilentlyContinue
                Write-Log "  [+] Added BdActr$domainNetBIOS`12 to Server Operators" -Level SUCCESS
            }
        }
        
        # Domain Admins
        $badActor22 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`22" } -ErrorAction SilentlyContinue
        if ($badActor22) {
            $domainAdminsGroup = Get-ADGroup -Filter { SamAccountName -eq "Domain Admins" } -ErrorAction SilentlyContinue
            if ($domainAdminsGroup) {
                Add-ADGroupMember -Identity $domainAdminsGroup -Members $badActor22 -ErrorAction SilentlyContinue
                Write-Log "  [+] Added BdActr$domainNetBIOS`22 to Domain Admins" -Level SUCCESS
            }
        }
    }
    catch {
        Write-Log "  [X] Failed to add members to protected groups: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Grant LAPS and computer permissions
    Write-Log "Granting LAPS and computer permissions..." -Level WARNING
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
            Write-Log "  [+] Granted LAPS and computer permissions on TEST OU computers" -Level SUCCESS
        }
    }
    catch {
        Write-Log "  [X] Failed to grant computer permissions: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Grant Domain NC replication and ownership rights
    Write-Log "Granting Domain NC replication and ownership rights..." -Level WARNING
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
            Write-Log "  [+] Granted Replicate Changes All to BdActr$domainNetBIOS`17" -Level SUCCESS
        }
        
        # Set Owner
        $badActor18 = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`18" } -ErrorAction SilentlyContinue
        if ($badActor18) {
            $badActorSID = New-Object System.Security.Principal.SecurityIdentifier($badActor18.SID)
            $domainObj.psbase.objectSecurity.SetOwner($badActorSID)
            Write-Log "  [+] Set BdActr$domainNetBIOS`18 as owner of Domain NC" -Level SUCCESS
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
            Write-Log "  [+] Granted WriteDACL to BdActr$domainNetBIOS`19" -Level SUCCESS
        }
        
        $domainObj.psbase.commitchanges()
    }
    catch {
        Write-Log "  [X] Failed to grant Domain NC rights: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    # Configure Machine Account Quota
    Write-Log "Configuring Machine Account Quota..." -Level WARNING
    try {
        $domainObj = [ADSI]("LDAP://$rwdcFQDN/$domainDN")
        $newQuota = Get-Random -Minimum 1 -Maximum 25
        $domainObj.Put("ms-DS-MachineAccountQuota", $newQuota)
        $domainObj.SetInfo()
        Write-Log "  [+] Set Machine Account Quota to $newQuota" -Level SUCCESS
    }
    catch {
        Write-Log "  [X] Failed to configure Machine Account Quota: $_" -Level ERROR
    }
    Write-Log "" -Level INFO
    
    Write-Log "AD delegations and security misconfigurations completed" -Level INFO
    Write-Log "" -Level INFO
}

Export-ModuleMember -Function Invoke-ModuleADDelegations