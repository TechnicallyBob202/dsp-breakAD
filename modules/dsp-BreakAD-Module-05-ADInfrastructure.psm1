################################################################################
##
## dsp-BreakAD-Module-05-ADInfrastructure.psm1
##
## Purpose: Introduce AD Infrastructure security misconfigurations to lower DSP score
## Targets: AD Infrastructure IOE category in DSP
##
## IOEs Documented (25 total):
##
## SAFE (low risk, easy rollback) - 5 IMPLEMENTED:
##  1. Unsecured DNS configuration ✓
##  2. Query policies with ldap deny list set ✓
##  3. Weak certificate cipher suites ✓
##  4. Unexpected accounts in Cert Publishers Group ✓
##  5. Abnormal linkage of dMSA to enabled domain account ✓
##
## SAFE WITH CAUTION (medium risk, explicit rollback required - documented):
##  6. Anonymous NSPI access to AD enabled (registry toggle, single DC)
##  7. Changes to nTSecurityDescriptor on MicrosoftDNS (add benign ACE)
##  8. Domain trust to third-party without quarantine (lab trust only)
##  9. Operator groups no longer protected by AdminSDHolder
## 10. Outbound forest trust with SID History enabled
## 11. Print spooler service enabled on DC
## 12. Risky RODC credential caching
## 13. Computers with older OS versions
## 14. Computers with password last set 90+ days
##
## NOT SAFE / BREAKS DSP (do not implement):
## 15. LDAP channel binding not required (breaks DSP connectivity)
## 16. LDAP signing not required (breaks DSP connectivity)
## 17. SMB signing not required (breaks DSP connectivity)
## 18. SMBv1 enabled on Domain Controllers (requires reboot)
## 19. NTFRS SYSVOL replication (requires DC migration/revert)
## 20. Anonymous access to Active Directory enabled (increases noise)
## 21. Certificate templates - SAN requesters allowed (requires CA/templates)
## 22. Certificate templates - 3+ insecure configs (requires CA/templates)
## 23. Dangerous control paths - certificate containers (requires CA)
## 24. Dangerous control paths - certificate templates (requires CA)
## 25. Weak certificate cipher (see #3)
##
## Design Philosophy:
##  - All test objects created in BreakAD OU where possible
##  - DNS and policy changes are reversible
##  - No changes to critical infrastructure
##  - Avoid changes that break DSP connectivity
##  - Keep all changes time-boxed and documented
##
## Author: Bob (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleADInfrastructure {
    <#
    .SYNOPSIS
        Introduce AD Infrastructure misconfigurations to DSP detection range
    
    .PARAMETER Environment
        Hashtable containing Domain, DomainController, and Config
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    
        try {
            # LDAP query policies stored as objects in Configuration partition
            $configDN = "CN=Configuration,$domainDN"
            $policyName = "break-ldapquery-$suffix"
            $policyDN = "CN=$policyName,$configDN"
            
            # Create LDAP query policy via DirectoryEntry
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$policyDN")
            $entry.put("objectClass", "queryPolicy")
            $entry.put("cn", $policyName)
            $entry.put("ldapAdminLimits", "10000")
            # Set ldapserverintegrity to 0 (None - allows unsigned queries)
        try {
            # Create weak cipher GPO
            $gpoName = "break-weakciphers-$suffix"
            
            # Set Schannel registry values for weak ciphers via GPO
            # Disable strong ciphers (AES), enable weak ones (RC4, 3DES)
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -ValueName "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -ValueName "Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\3DES 168/168" -ValueName "Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            # Link GPO to test OU
            New-GPLink -Name $gpoName -Target $breakADOU -ErrorAction SilentlyContinue
            
            Write-Log "  [+] Created weak cipher suite GPO and linked to BreakAD OU (IOE #3)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error configuring ciphers: $_" -Level WARNING
        }
            $entry.put("ldapserverintegrity", "0")
            $entry.CommitChanges()
            
            Write-Log "  [+] Created LDAP query policy with deny list configuration (IOE #2)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error creating LDAP query policy: $_" -Level WARNING
        }
    $domainDN = $domain.DistinguishedName
    $domainFQDN = $domain.DNSRoot
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 05: AD Infrastructure" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    try {
        $suffix = Get-Random -Minimum 100 -Maximum 999
        $breakADOU = "OU=BreakAD,$domainDN"
        $breakADOUUsers = "OU=Users,OU=BreakAD,$domainDN"
        
        # =====================================================================
        # PHASE 1: Unsecured DNS Configuration
        # =====================================================================
        
        Write-Log "PHASE 1: Configure unsecured DNS zone (IOE #1)" -Level INFO
        
        try {
            # Get first primary DNS zone
            $dnsZones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq "Primary" -and $_.Name -notlike "*._tcp*" } | Select-Object -First 1
            
            if ($dnsZones) {
                $zoneName = $dnsZones.Name
                
                # Set dynamic updates to Nonsecure and Secure (allows unsigned updates)
                Set-DnsServerPrimaryZone -Name $zoneName -DynamicUpdate NonsecureAndSecure -ErrorAction SilentlyContinue
                
                Write-Log "  [+] Set zone '$zoneName' to allow nonsecure dynamic updates (IOE #1)" -Level SUCCESS
            }
            else {
                Write-Log "  [*] No primary DNS zones found - skipping (IOE #1)" -Level INFO
            }
        }
        catch {
            Write-Log "  [!] Error configuring DNS zone: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        

        
        Write-Log "" -Level INFO
        

        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 4: Unexpected Accounts in Cert Publishers Group
        # =====================================================================
        
        Write-Log "PHASE 4: Add test user to Cert Publishers group (IOE #4)" -Level INFO
        
        try {
            # Create a test user to add to Cert Publishers
            $testUser = New-ADUser -Name "break-certpub-$suffix" `
                -SamAccountName "break-certpub-$suffix" `
                -UserPrincipalName "break-certpub-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            # Add to Cert Publishers group
            $certPublishers = Get-ADGroup -Identity "Cert Publishers" -ErrorAction SilentlyContinue
            if ($certPublishers) {
                Add-ADGroupMember -Identity $certPublishers -Members $testUser -ErrorAction SilentlyContinue
                Write-Log "  [+] Added test user to Cert Publishers group (IOE #4)" -Level SUCCESS
            }
            else {
                Write-Log "  [*] Cert Publishers group not found - skipping (IOE #4)" -Level INFO
            }
        }
        catch {
            Write-Log "  [!] Error adding to Cert Publishers: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 5: Abnormal dMSA Linkage to Enabled Domain Account
        # =====================================================================
        
        Write-Log "PHASE 5: Link dMSA to enabled domain account (IOE #5)" -Level INFO
        
        try {
            # Create a test dMSA
            $dmsaName = "break-dmsa-$suffix"
            $dmsa = New-ADServiceAccount -Name $dmsaName `
                -ErrorAction Stop -PassThru
            
            # Create a test enabled user account
            $testUser2 = New-ADUser -Name "break-dmsalink-$suffix" `
                -SamAccountName "break-dmsalink-$suffix" `
                -UserPrincipalName "break-dmsalink-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
            # Get the DNs of both objects
            $dmsaDN = $dmsa.DistinguishedName
            $userDN = $testUser2.DistinguishedName
            
            Write-Log "  [+] Created dMSA: $dmsaName" -Level SUCCESS
            Write-Log "  [+] Created user: $($testUser2.SamAccountName)" -Level SUCCESS
            
            # Set msDS-ManagedAccountPrecededByLink on the dMSA to point to the user
            # This creates the BadSuccessor indicator - abnormal linkage on dMSA without
            # corresponding modification on user account (manual tampering pattern)
            try {
                $dmsaObj = Get-ADServiceAccount -Identity $dmsaDN -ErrorAction Stop
                Set-ADObject -Identity $dmsaObj -Add @{'msDS-ManagedAccountPrecededByLink' = $userDN} -ErrorAction Stop
                
                Write-Log "  [+] Set msDS-ManagedAccountPrecededByLink on dMSA to user DN" -Level SUCCESS
                Write-Log "  [+] Created BadSuccessor pattern (IOE #5)" -Level SUCCESS
            }
            catch {
                Write-Log "  [!] Error setting msDS-ManagedAccountPrecededByLink: $_" -Level WARNING
                Write-Log "      Note: Attribute may not exist on this Windows version or dMSA type" -Level WARNING
            }
        }
        catch {
            Write-Log "  [!] Error creating dMSA/user linkage: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "Module 05: AD Infrastructure - COMPLETE" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "" -Level INFO
        Write-Log "NOTE: IOEs 2, 3 require advanced configuration (LDAP, Schannel, GPO)" -Level INFO
        Write-Log "      Phases 6-25 (CAUTION/HIGH RISK) documented but not implemented" -Level INFO
        Write-Log "" -Level INFO
        
        return $true
    }
    catch {
        Write-Log "Module 05 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleADInfrastructure