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
            # PHASE 2: Configure GPOs with dangerous settings
            # =====================================================================
            Write-Host "PHASE 2: Configuring GPO misconfigurations..." -ForegroundColor Cyan
            
            foreach ($gpo in $createdGPOs) {
                Write-Host "  Configuring: $($gpo.DisplayName)" -ForegroundColor Yellow
                
                try {
                    # Get the GPO root path for registry preference modifications
                    $gpoPath = "\\$domainFQDN\SYSVOL\$domainFQDN\Policies\$($gpo.Id)"
                    
                    # Create Machine\Preferences directories
                    $prefsPath = "$gpoPath\Machine\Preferences"
                    New-Item -ItemType Directory -Path "$prefsPath\System" -Force -ErrorAction SilentlyContinue | Out-Null
                    New-Item -ItemType Directory -Path "$prefsPath\Shortcuts" -Force -ErrorAction SilentlyContinue | Out-Null
                    New-Item -ItemType Directory -Path "$prefsPath\ScheduledTasks" -Force -ErrorAction SilentlyContinue | Out-Null
                    
                    # 2A: Write dangerous user rights to GptTmpl.inf
                    $secEditPath = "$gpoPath\Machine\Microsoft\Windows NT\SecEdit"
                    New-Item -ItemType Directory -Path $secEditPath -Force -ErrorAction SilentlyContinue | Out-Null
                    
                    $userRightsContent = @"
[Unicode]
Unicode=yes
[System Access]
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-545
SeTcbPrivilege = *S-1-5-11
SeTakeOwnershipPrivilege = *S-1-5-32-546
"@
                    Set-Content -Path "$secEditPath\GptTmpl.inf" -Value $userRightsContent -Force -ErrorAction SilentlyContinue
                    Write-Host "    [+] Dangerous user rights configured (SeDebugPrivilege, SeTcbPrivilege, SeTakeOwnershipPrivilege)" -ForegroundColor Green
                    
                    # 2B: Write reversible password storage to Registry.xml
                    $regXmlPath = "$prefsPath\Registry"
                    New-Item -ItemType Directory -Path $regXmlPath -Force -ErrorAction SilentlyContinue | Out-Null
                    
                    $reversibleContent = @"
<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{6A64AB20-45BC-4148-A268-2F1A681B365D}" displayName="Reversible Password Storage">
  <Registry clsid="{9CD4B327-50FB-46f4-9B9E-F8F167743C90}" name="HKLM\System\CurrentControlSet\Control\Lsa\StorePasswordUsingReversibleEncryption" status="1" image="1">
    <Property name="DWORD" displayName="Value" type="1">1</Property>
  </Registry>
</RegistrySettings>
"@
                    Set-Content -Path "$regXmlPath\Reversible.xml" -Value $reversibleContent -Force -ErrorAction SilentlyContinue
                    Write-Host "    [+] Reversible password encryption configured" -ForegroundColor Green
                    
                    # 2C: Write LM hash weak storage
                    $lmHashContent = @"
<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{6A64AB20-45BC-4148-A268-2F1A681B365D}" displayName="LM Hash Storage">
  <Registry clsid="{9CD4B327-50FB-46f4-9B9E-F8F167743C90}" name="HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash" status="0" image="0">
    <Property name="DWORD" displayName="Value" type="1">0</Property>
  </Registry>
</RegistrySettings>
"@
                    Set-Content -Path "$regXmlPath\LMHash.xml" -Value $lmHashContent -Force -ErrorAction SilentlyContinue
                    Write-Host "    [+] LM hash weak storage configured" -ForegroundColor Green
                    
                    # 2D: Create writable shortcuts
                    $shortcutsPath = "$prefsPath\Shortcuts"
                    $shortcutContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Shortcuts clsid="{D6CCE082-354D-11D2-8CEB-00C04FB681B5}" displayName="Shortcut Configuration">
  <Shortcut clsid="{1F4DE499-FFF6-11D1-895E-00A0C90AB505}" name="WritableShortcut" status="1" image="1">
    <Properties name="WritableTarget" targets="\\SYSVOL\Writable" location="%UserProfile%\Desktop" />
  </Shortcut>
</Shortcuts>
"@
                    Set-Content -Path "$shortcutsPath\Shortcuts.xml" -Value $shortcutContent -Force -ErrorAction SilentlyContinue
                    Write-Host "    [+] Writable shortcuts configured" -ForegroundColor Green
                    
                    # 2E: Dangerous logon script path
                    $logonScriptContent = @"
<?xml version="1.0" encoding="utf-8"?>
<ScriptSettings clsid="{42B5BEDF-86D3-4314-B25E-3B3EE46250EC}" displayName="Logon Script">
  <Script clsid="{73E4DB60-4A8C-11D1-A9C6-00AA004CD65C}" name="LogonScript" status="1">
    <Properties scriptPath="\\$domainFQDN\SYSVOL\$domainFQDN\Policies\scripts\malicious.bat" />
  </Script>
</ScriptSettings>
"@
                    Set-Content -Path "$prefsPath\LogonScript.xml" -Value $logonScriptContent -Force -ErrorAction SilentlyContinue
                    Write-Host "    [+] Dangerous logon script path configured" -ForegroundColor Green
                    
                    # 2F: Scheduled tasks in GPO
                    $tasksPath = "$prefsPath\ScheduledTasks"
                    $taskContent = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4BA0-B154-A71CD118DBCC}" displayName="Scheduled Task Configuration">
  <Task clsid="{D8896823-B82B-11D1-A9C6-00AA004CD65C}" name="SuspiciousTask" status="1">
    <Properties taskName="SuspiciousTask" taskType="0" action="C:\Windows\System32\cmd.exe" />
  </Task>
</ScheduledTasks>
"@
                    Set-Content -Path "$tasksPath\Tasks.xml" -Value $taskContent -Force -ErrorAction SilentlyContinue
                    Write-Host "    [+] Scheduled tasks configured in GPO" -ForegroundColor Green
                    
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