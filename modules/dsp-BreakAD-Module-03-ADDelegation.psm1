################################################################################
##
## dsp-BreakAD-Module-03-ADDelegation.psm1
##
## Configures AD delegation misconfigurations
## - Grant dangerous permissions to non-admin users
## - Create computers with unconstrained delegation
## - Modify ACLs on sensitive objects
## - Grant reset password rights to weak users
## - Delegation ACL abuse
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleADDelegation {
    <#
    .SYNOPSIS
        Applies AD delegation misconfigurations
    
    .PARAMETER Environment
        Hashtable containing Domain and DomainController info
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    $successCount = 0
    $errorCount = 0
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    
    Write-Log "AD Delegation Module Starting" -Level INFO
    Write-Log "Domain: $($domain.Name)" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # GRANT DANGEROUS PERMISSIONS
    ################################################################################
    
    if ($config['ADDelegation_GrantDangerousPermissions'] -eq 'true') {
        Write-Log "Granting dangerous permissions to non-admin users..." -Level INFO
        
        try {
            # Try to find or create a test user to grant permissions to
            $testUser = Get-ADUser -Identity "break-User-1" -ErrorAction SilentlyContinue
            if (-not $testUser) {
                Write-Log "  [*] Test user break-User-1 not found, skipping permission grants" -Level INFO
            }
            else {
                # Grant permissions on Users container
                $usersContainer = Get-ADObject -Identity "CN=Users,$domainDN" -ErrorAction Stop
                
                try {
                    # Add permissions: Reset Password, Modify Group Membership
                    $acl = Get-Acl -Path "AD:\$($usersContainer.DistinguishedName)"
                    $userSID = $testUser.SID
                    
                    # Reset Password permission (GUID: 00299570-246d-11d0-a768-00aa006e0529)
                    $resetPwGUID = [GUID]"00299570-246d-11d0-a768-00aa006e0529"
                    $resetPwRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $userSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $resetPwGUID
                    )
                    $acl.AddAccessRule($resetPwRule)
                    
                    Set-Acl -Path "AD:\$($usersContainer.DistinguishedName)" -AclObject $acl -ErrorAction Stop
                    
                    Write-LogChange -Object "Users Container" -Attribute "Permissions" -OldValue "Restricted" -NewValue "Reset Password Granted to $($testUser.Name)"
                    Write-Log "  [+] Reset Password permission granted on Users container" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error granting container permissions: $_" -Level WARNING
                    $errorCount++
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # COMPUTER WITH UNCONSTRAINED DELEGATION
    ################################################################################
    
    if ($config['ADDelegation_IncludeComputerDelegation'] -eq 'true') {
        Write-Log "Creating computer with unconstrained delegation..." -Level INFO
        
        try {
            $computerName = "BREAK-COMP-01"
            $computerDN = "CN=$computerName,CN=Computers,$domainDN"
            
            # Check if exists
            $existingComputer = Get-ADComputer -Identity $computerName -ErrorAction SilentlyContinue
            if (-not $existingComputer) {
                New-ADComputer -Name $computerName -Enabled $true -ErrorAction Stop
                Write-Log "  [+] Computer created: $computerName" -Level SUCCESS
            }
            else {
                Write-Log "  [*] Computer already exists: $computerName" -Level INFO
            }
            
            $computer = Get-ADComputer -Identity $computerName -ErrorAction Stop
            
            # Enable unconstrained delegation
            Set-ADComputer -Identity $computer -TrustedForDelegation $true -ErrorAction Stop
            Write-LogChange -Object $computerName -Attribute "TrustedForDelegation" -OldValue "False" -NewValue "True"
            Write-Log "  [+] Unconstrained delegation enabled on $computerName" -Level SUCCESS
            $successCount++
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # MODIFY SENSITIVE OBJECT ACLs
    ################################################################################
    
    if ($config['ADDelegation_ModifySensitiveACLs'] -eq 'true') {
        Write-Log "Modifying ACLs on sensitive objects..." -Level INFO
        
        try {
            $testUser = Get-ADUser -Identity "break-User-1" -ErrorAction SilentlyContinue
            if (-not $testUser) {
                Write-Log "  [*] Test user break-User-1 not found, skipping ACL modifications" -Level INFO
            }
            else {
                # Get sensitive objects
                $groupsContainer = Get-ADObject -Filter "objectClass -eq 'organizationalUnit'" -SearchBase $domainDN -ErrorAction Stop | Select-Object -First 1
                
                if ($groupsContainer) {
                    try {
                        $acl = Get-Acl -Path "AD:\$($groupsContainer.DistinguishedName)"
                        $userSID = $testUser.SID
                        
                        # Add write permission
                        $writeRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $userSID,
                            [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                        $acl.AddAccessRule($writeRule)
                        
                        Set-Acl -Path "AD:\$($groupsContainer.DistinguishedName)" -AclObject $acl -ErrorAction Stop
                        
                        Write-LogChange -Object $groupsContainer.Name -Attribute "GenericWrite Permission" -OldValue "Restricted" -NewValue "Granted to $($testUser.Name)"
                        Write-Log "  [+] GenericWrite permission granted" -Level SUCCESS
                        $successCount++
                    }
                    catch {
                        Write-Log "    [!] Error modifying ACLs: $_" -Level WARNING
                        $errorCount++
                    }
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # GRANT RESET PASSWORD RIGHTS
    ################################################################################
    
    if ($config['ADDelegation_GrantResetPasswordRights'] -eq 'true') {
        Write-Log "Granting reset password rights to non-admin users..." -Level INFO
        
        try {
            $testUser = Get-ADUser -Identity "break-User-2" -ErrorAction SilentlyContinue
            if (-not $testUser) {
                Write-Log "  [*] Test user break-User-2 not found, skipping" -Level INFO
            }
            else {
                # Find a target user to grant reset rights on
                $targetUser = Get-ADUser -Identity "break-User-3" -ErrorAction SilentlyContinue
                if ($targetUser) {
                    try {
                        $acl = Get-Acl -Path "AD:\$($targetUser.DistinguishedName)"
                        $userSID = $testUser.SID
                        
                        # Reset Password extended right GUID: 00299570-246d-11d0-a768-00aa006e0529
                        $resetPwGUID = [GUID]"00299570-246d-11d0-a768-00aa006e0529"
                        $resetPwRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $userSID,
                            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                            [System.Security.AccessControl.AccessControlType]::Allow,
                            $resetPwGUID
                        )
                        $acl.AddAccessRule($resetPwRule)
                        
                        Set-Acl -Path "AD:\$($targetUser.DistinguishedName)" -AclObject $acl -ErrorAction Stop
                        
                        Write-LogChange -Object $testUser.Name -Attribute "Reset Password Rights" -OldValue "None" -NewValue $targetUser.Name
                        Write-Log "  [+] Reset password rights granted: $($testUser.Name) -> $($targetUser.Name)" -Level SUCCESS
                        $successCount++
                    }
                    catch {
                        Write-Log "    [!] Error granting reset password rights: $_" -Level WARNING
                        $errorCount++
                    }
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # SUMMARY
    ################################################################################
    
    Write-Log "AD Delegation Module Complete" -Level INFO
    Write-Log "Successful changes: $successCount" -Level SUCCESS
    if ($errorCount -gt 0) {
        Write-Log "Errors encountered: $errorCount" -Level WARNING
        return $false
    }
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleADDelegation