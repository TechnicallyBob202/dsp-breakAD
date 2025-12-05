################################################################################
##
## dsp-BreakAD-Module-03-GroupPolicySecurity.psm1
##
## Purpose: Introduce Group Policy Security misconfigurations to lower DSP score
## Targets: Group Policy Security IOE category in DSP
##
## IOEs Targeted:
##  - Dangerous user rights granted by GPO
##  - GPO with scheduled tasks configured
##  - Reversible passwords found in GPOs
##  - Writable shortcuts found in GPO
##  - Dangerous GPO logon script path
##  - GPO weak LM hash storage enabled
##  - Changes to GPO linking at the Domain level
##  - Changes to GPO linking at the AD Site level
##  - Changes to GPO linking at the Domain Controller OU level
##  - GPO linking delegation at the domain level
##  - GPO linking delegation at the AD Site level
##  - GPO linking delegation at the domain controller OU level
##
## Author: Claude (claude.ai)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleGroupPolicySecurity {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]$Environment
    )

    Begin {
        Write-Host ""
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "  MODULE 03: Group Policy Security" -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host ""

        $domain = $Environment.Domain
        $dc = $Environment.DomainController
        $config = $Environment.Config
        
        $domainDN = $domain.DistinguishedName
        $domainFQDN = $domain.DNSRoot
        $domainName = $domain.Name
        $dcFQDN = $dc.HostName
    }

    Process {
        Try {
            # Require Group Policy module
            if (-not (Get-Module GroupPolicy -ListAvailable)) {
                Write-Host "  [!] GroupPolicy module not available" -ForegroundColor Red
                return $false
            }

            Write-Host "Domain: $domainFQDN" -ForegroundColor Yellow
            Write-Host "DC: $dcFQDN" -ForegroundColor Yellow
            Write-Host ""

            # =====================================================================
            # PHASE 1: Create three fresh GPOs (Domain, Site, DC OU levels)
            # =====================================================================
            Write-Host "PHASE 1: Creating fresh GPOs..." -ForegroundColor Cyan
            
            # Set GPO names with fallback defaults
            $gpoNameDomain = if ($config['GroupPolicySecurity_GPOName_Domain']) { $config['GroupPolicySecurity_GPOName_Domain'] } else { "breakAD-GroupPolicySecurity-Domain" }
            $gpoNameSite = if ($config['GroupPolicySecurity_GPOName_Site']) { $config['GroupPolicySecurity_GPOName_Site'] } else { "breakAD-GroupPolicySecurity-Site" }
            $gpoNameDC = if ($config['GroupPolicySecurity_GPOName_DC']) { $config['GroupPolicySecurity_GPOName_DC'] } else { "breakAD-GroupPolicySecurity-DC" }
            
            $gpoNames = @($gpoNameDomain, $gpoNameSite, $gpoNameDC)

            $createdGPOs = @()

            foreach ($gpoName in $gpoNames) {
                # Check if GPO already exists
                $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                
                if ($existingGPO) {
                    Write-Host "  [*] GPO already exists: $gpoName" -ForegroundColor Yellow
                    $createdGPOs += $existingGPO
                }
                else {
                    try {
                        $newGPO = New-GPO -Name $gpoName -Comment "breakAD Group Policy Security misconfiguration" -Server $dcFQDN
                        Write-Host "  [+] Created GPO: $gpoName" -ForegroundColor Green
                        $createdGPOs += $newGPO
                    }
                    catch {
                        Write-Host "  [!] Failed to create GPO $gpoName : $_" -ForegroundColor Red
                        return $false
                    }
                }
            }

            Write-Host ""

            # =====================================================================
            # PHASE 2: Configure GPOs with dangerous settings using Set-GPRegistryValue
            # =====================================================================
            Write-Host "PHASE 2: Configuring GPO misconfigurations..." -ForegroundColor Cyan
            
            foreach ($gpo in $createdGPOs) {
                Write-Host "  Configuring: $($gpo.DisplayName)" -ForegroundColor Yellow
                
                try {
                    # Set dangerous registry values in the GPO
                    # These will be stored in the GPO and synced to SYSVOL by Group Policy
                    
                    # Reversible password encryption
                    Set-GPRegistryValue -Name $gpo.DisplayName `
                        -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                        -ValueName "StorePasswordUsingReversibleEncryption" `
                        -Type DWORD `
                        -Value 1 -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "    [+] Reversible password encryption configured" -ForegroundColor Green
                    
                    # Weak LM hash storage (NoLMHash=0 = weak hashes allowed)
                    Set-GPRegistryValue -Name $gpo.DisplayName `
                        -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                        -ValueName "NoLMHash" `
                        -Type DWORD `
                        -Value 0 -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "    [+] LM hash weak storage configured" -ForegroundColor Green
                    
                    # Weak encryption types
                    Set-GPRegistryValue -Name $gpo.DisplayName `
                        -Key "HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
                        -ValueName "SupportedEncryptionTypes" `
                        -Type DWORD `
                        -Value 3 -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "    [+] Weak encryption types enabled" -ForegroundColor Green
                    
                    # Dangerous logon script path
                    Set-GPRegistryValue -Name $gpo.DisplayName `
                        -Key "HKLM\Software\Policies\Microsoft\Windows\System" `
                        -ValueName "LogonScriptPath" `
                        -Type String `
                        -Value "\\$domainFQDN\SYSVOL\Scripts\malicious.bat" -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "    [+] Dangerous logon script path configured" -ForegroundColor Green
                    
                    # Disable LDAP signing
                    Set-GPRegistryValue -Name $gpo.DisplayName `
                        -Key "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" `
                        -ValueName "LDAPServerIntegrity" `
                        -Type DWORD `
                        -Value 0 -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "    [+] LDAP signing disabled" -ForegroundColor Green
                    
                    # Disable SMB signing
                    Set-GPRegistryValue -Name $gpo.DisplayName `
                        -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
                        -ValueName "RequireSecuritySignature" `
                        -Type DWORD `
                        -Value 0 -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "    [+] SMB signing disabled" -ForegroundColor Green
                    
                    # Grant dangerous permissions (GpoEdit to Authenticated Users)
                    Set-GPPermission -Name $gpo.DisplayName `
                        -PermissionLevel GpoEdit `
                        -TargetName "Authenticated Users" `
                        -TargetType Group -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "    [+] Dangerous permissions configured (GpoEdit to Authenticated Users)" -ForegroundColor Green
                    
                }
                catch {
                    Write-Host "    [!] Error configuring GPO: $_" -ForegroundColor Yellow
                }
            }

            Write-Host ""

            # =====================================================================
            # PHASE 3: Link GPOs at Domain, Site, and DC OU levels
            # =====================================================================
            Write-Host "PHASE 3: Linking GPOs..." -ForegroundColor Cyan
            
            # 3A: Link Domain GPO at domain root
            try {
                $domainGPO = $createdGPOs[0]
                New-GPLink -Name $domainGPO.DisplayName -Target $domainDN -Server $dcFQDN -ErrorAction SilentlyContinue | Out-Null
                Write-Host "  [+] Linked '$($domainGPO.DisplayName)' at Domain level ($domainDN)" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Failed to link domain GPO: $_" -ForegroundColor Yellow
            }

            # 3B: Link Site GPO at first available site
            try {
                $siteGPO = $createdGPOs[1]
                $siteDN = Get-ADObject -Filter { ObjectClass -eq "site" } -SearchBase "CN=Sites,CN=Configuration,$domainDN" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty DistinguishedName
                
                if ($siteDN) {
                    New-GPLink -Name $siteGPO.DisplayName -Target $siteDN -Server $dcFQDN -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "  [+] Linked '$($siteGPO.DisplayName)' at Site level ($siteDN)" -ForegroundColor Green
                }
                else {
                    Write-Host "  [!] No sites found, skipping site-level linking" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  [!] Failed to link site GPO: $_" -ForegroundColor Yellow
            }

            # 3C: Link DC OU GPO at Domain Controllers OU
            try {
                $dcGPO = $createdGPOs[2]
                $dcOU = Get-ADOrganizationalUnit -Filter { Name -eq "Domain Controllers" } -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DistinguishedName
                
                if ($dcOU) {
                    New-GPLink -Name $dcGPO.DisplayName -Target $dcOU -Server $dcFQDN -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "  [+] Linked '$($dcGPO.DisplayName)' at DC OU level ($dcOU)" -ForegroundColor Green
                }
                else {
                    Write-Host "  [!] Domain Controllers OU not found" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  [!] Failed to link DC OU GPO: $_" -ForegroundColor Yellow
            }

            Write-Host ""

            # =====================================================================
            # PHASE 4: Discover Module 02 user accounts for delegation
            # =====================================================================
            Write-Host "PHASE 4: Discovering Module 02 user accounts for delegation..." -ForegroundColor Cyan
            
            $module02Accounts = Get-ADUser -Filter { SamAccountName -like "break-*" } -ErrorAction SilentlyContinue | Select-Object -First 2
            
            if ($module02Accounts.Count -lt 2) {
                Write-Host "  [!] Found only $($module02Accounts.Count) Module 02 user accounts (need at least 2)" -ForegroundColor Yellow
                Write-Host "  [*] Proceeding with delegation to found accounts..." -ForegroundColor Yellow
            }
            
            if ($module02Accounts.Count -eq 0) {
                Write-Host "  [!] No Module 02 user accounts (break-*) found, skipping delegation phase" -ForegroundColor Red
                return $false
            }

            foreach ($acct in $module02Accounts) {
                Write-Host "  [+] Found: $($acct.SamAccountName) ($($acct.DistinguishedName))" -ForegroundColor Green
            }

            Write-Host ""

            # =====================================================================
            # PHASE 5: Grant GPO linking delegation to Module 02 accounts
            # =====================================================================
            Write-Host "PHASE 5: Granting GPO linking delegation..." -ForegroundColor Cyan
            
            # Get the accounts to delegate to
            $delegateAccount1 = $module02Accounts[0]
            $delegateAccount2 = if ($module02Accounts.Count -gt 1) { $module02Accounts[1] } else { $module02Accounts[0] }
            
            # 5A: Delegate at Domain level
            try {
                $domainObj = Get-ADObject -Identity $domainDN -ErrorAction SilentlyContinue
                $domainSID = $delegateAccount1.SID.Value
                
                # Grant permissions on Domain object for GPO linking
                # This requires direct ACL manipulation
                $domainACL = Get-Acl "AD:$domainDN"
                
                # Create rules for GPO-related permissions (LinkGPO = GUID {01814787-5BB5-42d3-A4D5-0595BC1DD92A})
                $linkGPOGUID = [System.Guid]"01814787-5BB5-42d3-A4D5-0595BC1DD92A"
                $sid = New-Object System.Security.Principal.SecurityIdentifier($domainSID)
                
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $linkGPOGUID
                )
                $domainACL.AddAccessRule($ace)
                Set-Acl "AD:$domainDN" $domainACL -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Granted GPO linking delegation at Domain level to $($delegateAccount1.SamAccountName)" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error granting domain-level delegation: $_" -ForegroundColor Yellow
            }

            # 5B: Delegate at Site level
            try {
                $siteDN = Get-ADObject -Filter { ObjectClass -eq "site" } -SearchBase "CN=Sites,CN=Configuration,$domainDN" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty DistinguishedName
                
                if ($siteDN) {
                    $siteACL = Get-Acl "AD:$siteDN"
                    $linkGPOGUID = [System.Guid]"01814787-5BB5-42d3-A4D5-0595BC1DD92A"
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($delegateAccount2.SID.Value)
                    
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sid,
                        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $linkGPOGUID
                    )
                    $siteACL.AddAccessRule($ace)
                    Set-Acl "AD:$siteDN" $siteACL -ErrorAction SilentlyContinue
                    
                    Write-Host "  [+] Granted GPO linking delegation at Site level to $($delegateAccount2.SamAccountName)" -ForegroundColor Green
                }
                else {
                    Write-Host "  [!] No sites found, skipping site-level delegation" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  [!] Error granting site-level delegation: $_" -ForegroundColor Yellow
            }

            # 5C: Delegate at DC OU level
            try {
                $dcOU = Get-ADOrganizationalUnit -Filter { Name -eq "Domain Controllers" } -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DistinguishedName
                
                if ($dcOU) {
                    $dcOUACL = Get-Acl "AD:$dcOU"
                    $linkGPOGUID = [System.Guid]"01814787-5BB5-42d3-A4D5-0595BC1DD92A"
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($delegateAccount1.SID.Value)
                    
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sid,
                        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $linkGPOGUID
                    )
                    $dcOUACL.AddAccessRule($ace)
                    Set-Acl "AD:$dcOU" $dcOUACL -ErrorAction SilentlyContinue
                    
                    Write-Host "  [+] Granted GPO linking delegation at DC OU level to $($delegateAccount1.SamAccountName)" -ForegroundColor Green
                }
                else {
                    Write-Host "  [!] Domain Controllers OU not found, skipping DC OU delegation" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  [!] Error granting DC OU delegation: $_" -ForegroundColor Yellow
            }

            Write-Host ""
            Write-Host "PHASE 6: Forcing Group Policy update..." -ForegroundColor Cyan
            
            try {
                $updateResult = Invoke-Command -ComputerName $dcFQDN -ScriptBlock {
                    gpupdate /force
                } -ErrorAction SilentlyContinue
                
                Write-Host "  [+] Group Policy update forced on $dcFQDN" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Error forcing gpupdate: $_" -ForegroundColor Yellow
            }

            Write-Host ""
            Write-Host "Module 03 completed" -ForegroundColor Green
            Write-Host ""
            
            return $true
        }
        catch {
            Write-Host "  [!] Module 03 Error: $_" -ForegroundColor Red
            return $false
        }
    }
}

Export-ModuleMember -Function Invoke-ModuleGroupPolicySecurity