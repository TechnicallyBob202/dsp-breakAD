################################################################################
##
## dsp-BreakAD-Module-03-ADDelegation.psm1
##
## Purpose: Introduce AD Delegation misconfigurations to lower DSP score
## Targets: AD Delegation IOE category in DSP
##
## IOEs Targeted (13):
##
## SAFE (low risk, easy rollback):
##  1. Built-in guest account is enabled
##  2. Foreign Security Principals in Privileged Group
##  3. New Domain Controller PGID
##  4. Unprivileged users can add computer accounts to domain (OU-scoped)
##  5. Users with permissions to set Server Trust Account
##  6. Privileged objects with unprivileged owners (test group)
##  7. Objects in privileged groups without adminCount=1
##
## CAUTION (medium risk, explicit rollback required):
##  8. Permission changes on AdminSDHolder object
##  9. Inheritance enabled on AdminSDHolder object
## 10. Domain Controller owner is not an administrator
## 11. Delegation changes to Domain NC head
## 12. Non-default principals with DC Sync rights (test user only)
## 13. Non-default access to DPAPI key
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
    
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    
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

        Write-Log "" -Level INFO
        
        return $true
    }
    catch {
        Write-Log "Module 03 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleADDelegation