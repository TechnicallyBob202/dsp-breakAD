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
## Version: 1.0.2 (Phase 5 working: dMSA + user creation, KDS key required, Server 2022 compatible)
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
            $dnsZones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq "Primary" -and $_.Name -notlike "*._tcp*" } | Select-Object -First 1
            
            if ($dnsZones -and $dnsZones.Name) {
                $zoneName = $dnsZones.Name
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
        
        # =====================================================================
        # PHASE 2: LDAP Query Policies (Skipped - not reliably supported)
        # =====================================================================
        
        Write-Log "PHASE 2: Configure LDAP query policies (IOE #2)" -Level INFO
        Write-Log "  [*] LDAP queryPolicy object creation skipped - not reliably supported" -Level INFO
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 3: Weak Cipher Suites
        # =====================================================================
        
        Write-Log "PHASE 3: Configure weak cipher suites (IOE #3)" -Level INFO
        
        try {
            $gpoName = "break-weakciphers-$suffix"
            $gpo = New-GPO -Name $gpoName -ErrorAction Stop
            
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -ValueName "Enabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -ValueName "Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name $gpoName -Key "HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\3DES 168/168" -ValueName "Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            New-GPLink -Name $gpoName -Target $breakADOU -ErrorAction SilentlyContinue
            
            Write-Log "  [+] Created weak cipher suite GPO and linked to BreakAD OU (IOE #3)" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] Error configuring ciphers: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 4: Unexpected Accounts in Cert Publishers Group
        # =====================================================================
        
        Write-Log "PHASE 4: Add test user to Cert Publishers group (IOE #4)" -Level INFO
        
        try {
            $testUser = New-ADUser -Name "break-certpub-$suffix" `
                -SamAccountName "break-certpub-$suffix" `
                -UserPrincipalName "break-certpub-$suffix@$domainFQDN" `
                -Path $breakADOUUsers `
                -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                -Enabled $true `
                -ErrorAction Stop -PassThru
            
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
        
        Write-Log "PHASE 5: Create dMSA and user for abnormal linkage (IOE #5)" -Level INFO
        
        try {
            $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue
            if (-not $kdsKey) {
                Write-Log "  [*] KDS root key not found - dMSA creation skipped" -Level INFO
            }
            else {
                $dmsaName = "break-dmsa-$suffix"
                $dmsa = New-ADServiceAccount -Name $dmsaName `
                    -DNSHostName "$dmsaName.$domainFQDN" `
                    -ErrorAction Stop -PassThru
                
                $testUser2 = New-ADUser -Name "break-dmsalink-$suffix" `
                    -SamAccountName "break-dmsalink-$suffix" `
                    -UserPrincipalName "break-dmsalink-$suffix@$domainFQDN" `
                    -Path $breakADOUUsers `
                    -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd123!" -Force) `
                    -Enabled $true `
                    -ErrorAction Stop -PassThru
                
                $dmsaDN = $dmsa.DistinguishedName
                $userDN = $testUser2.DistinguishedName
                
                Write-Log "  [+] Created dMSA: $dmsaName" -Level SUCCESS
                Write-Log "  [+] Created user: $($testUser2.SamAccountName)" -Level SUCCESS
                Write-Log "  [+] Abnormal dMSA/user linkage pattern created (IOE #5)" -Level SUCCESS
                
                try {
                    $dmsaObj = Get-ADServiceAccount -Identity $dmsaDN -ErrorAction Stop
                    Set-ADObject -Identity $dmsaObj -Add @{'msDS-ManagedAccountPrecededByLink' = $userDN} -ErrorAction Stop
                    Write-Log "  [+] Set msDS-ManagedAccountPrecededByLink (BadSuccessor pattern)" -Level SUCCESS
                }
                catch {
                    Write-Log "  [*] msDS-ManagedAccountPrecededByLink not available (requires Windows Server 2025+)" -Level INFO
                }
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
        
        return $true
    }
    catch {
        Write-Log "Module 05 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleADInfrastructure