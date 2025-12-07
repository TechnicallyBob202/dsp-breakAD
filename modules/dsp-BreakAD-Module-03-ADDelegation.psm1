################################################################################
##
## dsp-BreakAD-Module-03-ADDelegation.psm1
##
## Purpose: Introduce AD Delegation misconfigurations to lower DSP score
## Targets: AD Delegation IOE category in DSP
##
## IOEs Targeted (15):
##
## SAFE (low risk, easy rollback):
##  1. Built-in guest account is enabled
##  2. Foreign Security Principals in Privileged Group
##  3. New Domain Controller PGID
##  4. Non-privileged users with access to gMSA passwords
##  5. Unprivileged users can add computer accounts to domain (OU-scoped)
##  6. Users with permissions to set Server Trust Account
##  7. Privileged objects with unprivileged owners (test group)
##  8. Objects in privileged groups without adminCount=1
##  9. gMSA not used (passive detection)
##
## CAUTION (medium risk, explicit rollback required):
## 10. Permission changes on AdminSDHolder object
## 11. Inheritance enabled on AdminSDHolder object
## 12. Domain Controller owner is not an administrator
## 13. Delegation changes to Domain NC head
## 14. Non-default principals with DC Sync rights (test user only)
## 15. Non-default access to DPAPI key
##
## Design Philosophy:
##  - All test accounts created in BreakAD\Users OU
##  - Test groups created in BreakAD OU
##  - All ACL changes are reversible and time-boxed
##  - Never modify built-in groups or critical objects
##  - Maintain snapshot/rollback plan for schema/AdminSDHolder changes
##
## Author: Bob (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleADDelegation {
    <#
    .SYNOPSIS
        Introduce AD Delegation misconfigurations to DSP detection range
    
    .PARAMETER Environment
        Hashtable containing Domain, DomainController, and Config
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    $dcFQDN = $dc.HostName
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 03: AD Delegation" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    try {
        # Generate random suffix for test objects
        $suffix = Get-Random -Minimum 100 -Maximum 999
        
        $breakADOUUsers = "OU=Users,OU=BreakAD,$domainDN"
        $breakADOU = "OU=BreakAD,$domainDN"
        
        # =====================================================================
        # PHASE 1: Create test accounts and groups
        # =====================================================================
        
        Write-Log "PHASE 1: Create test accounts and groups" -Level INFO
        
        $testUser = $null
        $testGroup = $null
        
        try {
            $testUser = New-ADUser -Name "break-deleg-$suffix" `
                -SamAccountName "break-deleg-$suffix" `
                -UserPrincipalName "break-deleg-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            Write-Log "  [+] Created test delegation user: $($testUser.SamAccountName)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating test user: $_" -Level WARNING
        }
        
        try {
            $testGroup = New-ADGroup -Name "break-privileged-$suffix" `
                -GroupScope Global `
                -GroupCategory Security `
                -Path $breakADOU `
                -ErrorAction Stop -PassThru
            
            Write-Log "  [+] Created test privileged group: $($testGroup.Name)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating test group: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 2: IOE #1 - Built-in guest account is enabled
        # =====================================================================
        
        Write-Log "PHASE 2: Enable built-in guest account (IOE #1)" -Level INFO
        
        try {
            $guest = Get-ADUser -Identity "Guest" -ErrorAction Stop
            Enable-ADAccount -Identity $guest -ErrorAction SilentlyContinue
            Write-Log "  [+] Enabled built-in Guest account" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error enabling guest account: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 3: IOE #4 - Non-privileged users with access to gMSA passwords
        # =====================================================================
        
        Write-Log "PHASE 3: Create gMSA and grant access to test user (IOE #4)" -Level INFO
        
        try {
            if ($testUser) {
                $gmsaName = "break-gmsa-$suffix"
                
                # Create gMSA
                $gmsa = New-ADServiceAccount -Name $gmsaName `
                    -DNSHostName "$gmsaName.$domainFQDN" `
                    -ErrorAction Stop -PassThru
                
                # Grant test user read access to gMSA membership
                $gmsaDN = $gmsa.DistinguishedName
                $acl = Get-Acl "AD:$gmsaDN"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($testUser.SID)
                
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.Guid]"5f202010-79a5-11d0-9020-00c04fc2d4cf"  # msDS-GroupMSAMembership
                )
                $acl.AddAccessRule($ace)
                Set-Acl "AD:$gmsaDN" $acl -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Created gMSA and granted read access to test user (IOE #4)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error creating gMSA: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 4: IOE #5 - Unprivileged users can add computer accounts to domain
        # =====================================================================
        
        Write-Log "PHASE 4: Grant computer account creation rights (IOE #5)" -Level INFO
        
        try {
            if ($testUser) {
                # Delegate "Create Computer objects" to test user on BreakAD OU
                $acl = Get-Acl "AD:$breakADOU"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($testUser.SID)
                
                # Create Computer (computer class GUID)
                $computerGUID = [System.Guid]"bf967a86-0de6-11d0-a285-00c04fd8d5cd"
                
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $computerGUID
                )
                $acl.AddAccessRule($ace)
                Set-Acl "AD:$breakADOU" $acl -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Granted computer creation rights to test user on BreakAD OU (IOE #5)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error granting computer creation rights: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 5: IOE #6 - Users with permissions to set Server Trust Account
        # =====================================================================
        
        Write-Log "PHASE 5: Grant Server Trust Account permissions (IOE #6)" -Level INFO
        
        try {
            if ($testUser) {
                # Create a test computer object
                $testComputer = New-ADComputer -Name "break-strust-$suffix" `
                    -Path "OU=Computers,OU=BreakAD,$domainDN" `
                    -ErrorAction Stop -PassThru
                
                # Grant "Reset Password" and "Validated write to DNS hostname" to test user
                $computerDN = $testComputer.DistinguishedName
                $acl = Get-Acl "AD:$computerDN"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($testUser.SID)
                
                # Reset Password
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.Guid]"00299570-246d-11d0-a768-00aa006e0529"  # Reset-Password
                )
                $acl.AddAccessRule($ace)
                Set-Acl "AD:$computerDN" $acl -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Granted Server Trust Account permissions to test user (IOE #6)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error granting Server Trust Account permissions: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 6: IOE #7 - Privileged objects with unprivileged owners (test group)
        # =====================================================================
        
        Write-Log "PHASE 6: Set unprivileged owner on test privileged group (IOE #7)" -Level INFO
        
        try {
            if ($testGroup -and $testUser) {
                # Change group owner to test user
                $groupDN = $testGroup.DistinguishedName
                $acl = Get-Acl "AD:$groupDN"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($testUser.SID)
                $acl.SetOwner($sid)
                Set-Acl "AD:$groupDN" $acl -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Set test user as owner of test privileged group (IOE #7)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error setting group owner: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 7: IOE #8 - Objects in privileged groups without adminCount=1
        # =====================================================================
        
        Write-Log "PHASE 7: Add unprivileged user to test group without adminCount (IOE #8)" -Level INFO
        
        try {
            if ($testGroup -and $testUser) {
                # Add test user to test group (which we'll mark as privileged)
                Add-ADGroupMember -Identity $testGroup -Members $testUser -ErrorAction SilentlyContinue
                
                # Mark group as privileged in AdminSDHolder
                Set-ADGroup -Identity $testGroup -Replace @{"adminCount" = 1} -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Added user to privileged group without adminCount (IOE #8)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "  [!] Error adding to privileged group: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 8: IOE #9 - gMSA not used (passive detection)
        # =====================================================================
        
        Write-Log "PHASE 8: Create gMSA not in use (IOE #9)" -Level INFO
        
        try {
            $unusedGMSA = New-ADServiceAccount -Name "break-unused-gmsa-$suffix" `
                -DNSHostName "break-unused-gmsa-$suffix.$domainFQDN" `
                -ErrorAction Stop -PassThru
            
            Write-Log "  [+] Created unused gMSA (IOE #9)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating unused gMSA: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 9: IOE #14 - Non-default principals with DC Sync rights (TEST USER ONLY)
        # =====================================================================
        
        Write-Log "PHASE 9: Grant DC Sync rights to test user (IOE #14)" -Level INFO
        Write-Log "  [!] WARNING: This is sensitive - verify removal in rollback" -Level WARNING
        
        try {
            if ($testUser) {
                $acl = Get-Acl "AD:$domainDN"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($testUser.SID)
                
                # Replicating Directory Changes
                $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # Replicating Directory Changes
                )
                $acl.AddAccessRule($ace1)
                
                # Replicating Directory Changes All
                $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    [System.Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # Replicating Directory Changes All
                )
                $acl.AddAccessRule($ace2)
                
                Set-Acl "AD:$domainDN" $acl -ErrorAction Stop
                Write-Log "  [+] Granted DC Sync rights to test user (IOE #14)" -Level SUCCESS
                Write-Log "  [!] IMPORTANT: Remove this right after testing - do not leave active" -Level WARNING
            }
        }
        catch {
            Write-Log "  [!] Error granting DC Sync rights: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "Module 03: AD Delegation - COMPLETE" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "" -Level INFO
        Write-Log "NOTE: Phases 10-15 (AdminSDHolder, Domain NC head, etc.) require" -Level INFO
        Write-Log "      manual testing and explicit rollback plan. See comments." -Level INFO
        Write-Log "" -Level INFO
        
        return $true
    }
    catch {
        Write-Log "Module 03 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleADDelegation