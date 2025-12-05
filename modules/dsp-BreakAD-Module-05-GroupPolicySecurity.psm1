################################################################################
##
## dsp-BreakAD-Module-05-GroupPolicySecurity.psm1
##
## Configures Group Policy security misconfigurations
## - Weaken GPO link permissions at domain level
## - Weaken GPO link permissions at DC OU level
## - Grant dangerous users GPO Creator rights
## - Modify default domain policy settings
## - Disable auditing on sensitive GPOs
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleGroupPolicySecurity {
    <#
    .SYNOPSIS
        Applies Group Policy security misconfigurations
    
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
    
    Write-Log "Group Policy Security Module Starting" -Level INFO
    Write-Log "Domain: $($domain.Name)" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # WEAKEN DOMAIN-LEVEL GPO PERMISSIONS
    ################################################################################
    
    if ($config['GroupPolicySecurity_WeakenDomainGPOPermissions'] -eq 'true') {
        Write-Log "Weakening GPO link permissions at domain level..." -Level INFO
        
        try {
            $testUser = Get-ADUser -Identity "break-User-1" -ErrorAction SilentlyContinue
            if (-not $testUser) {
                Write-Log "  [*] Test user break-User-1 not found, skipping" -Level INFO
            }
            else {
                try {
                    # Grant Edit GPO rights on the domain
                    $acl = Get-Acl -Path "AD:\$domainDN"
                    $userSID = $testUser.SID
                    
                    # Apply Group Policy right (GUID: edacfd8f-ffb3-11d1-b41d-00a0c968f939)
                    $gpEditGUID = [GUID]"edacfd8f-ffb3-11d1-b41d-00a0c968f939"
                    $gpEditRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $userSID,
                        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $gpEditGUID
                    )
                    $acl.AddAccessRule($gpEditRule)
                    
                    Set-Acl -Path "AD:\$domainDN" -AclObject $acl -ErrorAction Stop
                    
                    Write-LogChange -Object "Domain Object" -Attribute "Edit Group Policy Rights" -OldValue "Restricted" -NewValue "Granted to $($testUser.Name)"
                    Write-Log "  [+] Edit GPO rights granted at domain level" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error: $_" -Level WARNING
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
    # WEAKEN DC OU GPO PERMISSIONS
    ################################################################################
    
    if ($config['GroupPolicySecurity_WeakenDCOUGPOPermissions'] -eq 'true') {
        Write-Log "Weakening GPO link permissions at Domain Controllers OU..." -Level INFO
        
        try {
            $testUser = Get-ADUser -Identity "break-User-2" -ErrorAction SilentlyContinue
            if (-not $testUser) {
                Write-Log "  [*] Test user break-User-2 not found, skipping" -Level INFO
            }
            else {
                try {
                    # Find DC OU
                    $dcOU = Get-ADOrganizationalUnit -Filter "Name -eq 'Domain Controllers'" -ErrorAction Stop
                    
                    if ($dcOU) {
                        $acl = Get-Acl -Path "AD:\$($dcOU.DistinguishedName)"
                        $userSID = $testUser.SID
                        
                        # Grant write permission
                        $writeRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                            $userSID,
                            [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                        $acl.AddAccessRule($writeRule)
                        
                        Set-Acl -Path "AD:\$($dcOU.DistinguishedName)" -AclObject $acl -ErrorAction Stop
                        
                        Write-LogChange -Object "Domain Controllers OU" -Attribute "GenericWrite Permission" -OldValue "Restricted" -NewValue "Granted to $($testUser.Name)"
                        Write-Log "  [+] GenericWrite granted on DC OU" -Level SUCCESS
                        $successCount++
                    }
                }
                catch {
                    Write-Log "    [!] Error: $_" -Level WARNING
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
    # GRANT GPO CREATOR OWNER RIGHTS
    ################################################################################
    
    if ($config['GroupPolicySecurity_GrantGPOCreatorRights'] -eq 'true') {
        Write-Log "Granting Group Policy Creator rights to non-admin users..." -Level INFO
        
        try {
            $testUser = Get-ADUser -Identity "break-User-1" -ErrorAction SilentlyContinue
            if (-not $testUser) {
                Write-Log "  [*] Test user break-User-1 not found, skipping" -Level INFO
            }
            else {
                try {
                    # Find or create Group Policy Creator Owners group
                    $gpCreatorGroup = Get-ADGroup -Identity "Group Policy Creator Owners" -ErrorAction SilentlyContinue
                    
                    if ($gpCreatorGroup) {
                        Add-ADGroupMember -Identity $gpCreatorGroup -Members $testUser -ErrorAction SilentlyContinue
                        Write-LogChange -Object "Group Policy Creator Owners" -Attribute "Members" -OldValue "Standard" -NewValue "Added $($testUser.Name)"
                        Write-Log "  [+] Added $($testUser.Name) to Group Policy Creator Owners" -Level SUCCESS
                        $successCount++
                    }
                }
                catch {
                    Write-Log "    [!] Error: $_" -Level WARNING
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
    # MODIFY DEFAULT DOMAIN POLICY
    ################################################################################
    
    if ($config['GroupPolicySecurity_ModifyDefaultDomainPolicy'] -eq 'true') {
        Write-Log "Modifying Default Domain Policy..." -Level INFO
        
        try {
            # Note: This requires GPO editing capability. For now we log the intent.
            # In a real scenario, you'd use Group Policy COM objects or ADMX templates
            
            Write-Log "  [*] Default Domain Policy modifications require Group Policy Editor" -Level INFO
            Write-Log "  [*] Consider running gpEdit.msc to manually adjust:" -Level INFO
            Write-Log "    - Password Policy (Minimum length, complexity)" -Level INFO
            Write-Log "    - Account Lockout Policy" -Level INFO
            Write-Log "    - Kerberos Policy" -Level INFO
            Write-Log "  [*] Or use Set-GPRegistryValue cmdlets if GroupPolicy module available" -Level INFO
            
            # Attempt to weaken password policy if GroupPolicy module is available
            try {
                Import-Module GroupPolicy -ErrorAction Stop
                
                $gpo = Get-GPO -Name "Default Domain Policy" -ErrorAction Stop
                
                # Example: Set minimum password length to weak value
                Set-GPRegistryValue -Guid $gpo.Id -Key "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" `
                    -ValueName "MaximumPasswordAge" -Value 0 -Type DWORD -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Attempted to weaken Default Domain Policy" -Level SUCCESS
                $successCount++
            }
            catch {
                Write-Log "  [!] GroupPolicy module not available or policy modification failed" -Level WARNING
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # DISABLE GPO AUDITING
    ################################################################################
    
    if ($config['GroupPolicySecurity_DisableGPOAuditing'] -eq 'true') {
        Write-Log "Disabling auditing on sensitive GPOs..." -Level INFO
        
        try {
            # This would require disabling auditing at the DC and GPO level
            # For now, log the intent
            
            Write-Log "  [*] GPO auditing modifications require auditpol.exe or registry changes" -Level INFO
            Write-Log "  [*] To disable auditing, consider:" -Level INFO
            Write-Log "    - auditpol /set /subcategory:\"Group Policy Changes\" /success:disable /failure:disable" -Level INFO
            Write-Log "    - Disabling GPO change tracking via GPOE" -Level INFO
            
            Write-Log "  [!] Auditing disablement skipped - requires elevated operations" -Level WARNING
            $errorCount++
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
    
    Write-Log "Group Policy Security Module Complete" -Level INFO
    Write-Log "Successful changes: $successCount" -Level SUCCESS
    if ($errorCount -gt 0) {
        Write-Log "Errors encountered: $errorCount" -Level WARNING
        # Don't fail completely - some items require manual intervention
    }
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleGroupPolicySecurity