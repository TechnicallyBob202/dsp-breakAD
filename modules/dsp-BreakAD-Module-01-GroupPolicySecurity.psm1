################################################################################
##
## dsp-BreakAD-Module-01-GroupPolicySecurity.psm1
##
## Purpose: Introduce Group Policy Security misconfigurations to lower DSP score
## Targets: Group Policy Security IOE category in DSP
##
## IOEs Targeted (10):
##  1. Changes to Default Domain Policy or Default Domain Controllers Policy
##  2. Changes to GPO linking at the AD Site level
##  3. Changes to GPO linking at the Domain level
##  4. Dangerous GPO logon script path
##  5. Dangerous user rights granted by GPO
##  6. GPO linking delegation at the AD Site level
##  7. GPO linking delegation at the domain controller OU level
##  8. GPO linking delegation at the domain level
##  9. GPO weak LM hash storage enabled
## 10. SYSVOL Executable Changes
##
## Design Philosophy:
##  - All actions scoped to BreakAD OUs whenever possible
##  - No modifications to actual Default Domain/Controllers Policy (keep innocuous changes lit)
##  - GPO preferences set via Set-GPRegistryValue where applicable
##  - Logon scripts referenced in GPO but not created on SYSVOL
##  - Delegation granted on BreakAD OUs
##  - Link/unlink operations on test GPOs in BreakAD OU
##
## Author: Bob (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleGroupPolicySecurity {
    <#
    .SYNOPSIS
        Introduce Group Policy Security misconfigurations to DSP detection range
    
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
    Write-Log "Module 01: Group Policy Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    try {
        # =====================================================================
        # PHASE 1: Verify GroupPolicy module is available
        # =====================================================================
        
        Write-Log "PHASE 1: Validating GroupPolicy module" -Level INFO
        
        try {
            Import-Module GroupPolicy -ErrorAction Stop | Out-Null
            Write-Log "  [+] GroupPolicy module available" -Level SUCCESS
        }
        catch {
            Write-Log "  [!] GroupPolicy module not available: $_" -Level ERROR
            return $false
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 2: Modify Default Domain/Controllers Policies (keep them lit)
        # =====================================================================
        
        Write-Log "PHASE 2: Innocuous changes to Default Domain/Controllers Policies" -Level INFO
        Write-Log "  [*] IOE: Changes to Default Domain Policy/Controllers Policy" -Level INFO
        

                -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                -ValueName "SubmitControl" `
                -Value 1 `
                -Type DWORD `
                -ErrorAction Stop | Out-Null
            

                -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
                -ValueName "SubmitControl" `
                -Value 1 `
                -Type DWORD `
                -ErrorAction Stop | Out-Null
            
            Write-Log "    [+] Modified Default Domain Controllers Policy" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error modifying default policies: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 3: Create test GPOs for link/unlink operations
        # =====================================================================
        
        Write-Log "PHASE 3: Create test GPOs for link/unlink operations" -Level INFO
        
        $breakADOU = "OU=BreakAD,$domainDN"
        $gpoNames = @(
            "breakAD-LinkTest-Domain",
            "breakAD-LinkTest-Site",
            "breakAD-LinkTest-OU"
        )
        
        $createdGPOs = @()
        
        foreach ($gpoName in $gpoNames) {
            try {
                $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
                
                if ($existingGPO) {
                    Write-Log "    [*] GPO already exists: $gpoName" -Level INFO
                    $createdGPOs += $existingGPO
                }
                else {
                    $newGPO = New-GPO -Name $gpoName -Comment "breakAD test GPO for linking changes" -Server $dcFQDN -ErrorAction Stop
                    Write-Log "    [+] Created GPO: $gpoName" -Level SUCCESS
                    $createdGPOs += $newGPO
                }
            }
            catch {
                Write-Log "    [!] Error creating GPO $gpoName : $_" -Level ERROR
            }
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 4: IOE #2 & #3: Link/unlink GPOs at Domain and Site levels
        # =====================================================================
        
        Write-Log "PHASE 4: Link/unlink operations (IOE: Changes to GPO linking)" -Level INFO
        
        # Link at Domain level
        try {
            $domainGPO = $createdGPOs | Where-Object { $_.DisplayName -eq "breakAD-LinkTest-Domain" }
            
            if ($domainGPO) {
                # Check if already linked by trying to create and catching if exists
                try {
                    New-GPLink -Name $domainGPO.DisplayName -Target $breakADOU -Server $dcFQDN -ErrorAction Stop | Out-Null
                    Write-Log "    [+] Linked $($domainGPO.DisplayName) to BreakAD OU" -Level SUCCESS
                }
                catch {
                    if ($_ -like "*already*") {
                        Write-Log "    [*] GPO already linked at OU level" -Level INFO
                    }
                    else {
                        throw $_
                    }
                }
            }
        }
        catch {
            Write-Log "    [!] Error linking domain GPO: $_" -Level WARNING
        }
        
        # Link at Site level (to first available site)
        try {
            $siteGPO = $createdGPOs | Where-Object { $_.DisplayName -eq "breakAD-LinkTest-Site" }
            
            if ($siteGPO) {
                $siteDN = Get-ADObject -Filter { ObjectClass -eq "site" } `
                    -SearchBase "CN=Sites,CN=Configuration,$domainDN" `
                    -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty DistinguishedName
                
                if ($siteDN) {
                    try {
                        New-GPLink -Name $siteGPO.DisplayName -Target $siteDN -Server $dcFQDN -ErrorAction Stop | Out-Null
                        Write-Log "    [+] Linked $($siteGPO.DisplayName) to site: $siteDN" -Level SUCCESS
                    }
                    catch {
                        if ($_ -like "*already*") {
                            Write-Log "    [*] GPO already linked at site level" -Level INFO
                        }
                        else {
                            throw $_
                        }
                    }
                }
                else {
                    Write-Log "    [!] No sites found to link GPO" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "    [!] Error linking site GPO: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 5: IOE #5: Dangerous user rights granted by GPO
        # =====================================================================
        
        Write-Log "PHASE 5: Configure dangerous user rights in GPO" -Level INFO
        Write-Log "  [*] IOE: Dangerous user rights granted by GPO" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                # Create a non-privileged test user if needed
                $testUser = Get-ADUser -Filter { SamAccountName -eq "break-dangrights" } -ErrorAction SilentlyContinue
                
                if (-not $testUser) {
                    $testUser = New-ADUser -Name "break-dangrights" `
                        -SamAccountName "break-dangrights" `
                        -UserPrincipalName "break-dangrights@$domainFQDN" `
                        -Path "OU=Users,OU=BreakAD,$domainDN" `
                        -AccountPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force) `
                        -Enabled $true `
                        -ErrorAction SilentlyContinue -PassThru
                    
                    Write-Log "    [+] Created test user: break-dangrights" -Level SUCCESS
                }
                
                # Get user SID for GptTmpl.inf
                $userSID = $testUser.SID.Value
                
                # Create GptTmpl.inf with dangerous user rights assignments
                $gpoGUID = $rightGPO.Id.ToString().ToUpper()
                $gpoGUID = "{" + $gpoGUID + "}"
                $secEditDir = "C:\Windows\SYSVOL\sysvol\$domainFQDN\Policies\$gpoGUID\Machine\Microsoft\Windows NT\SecEdit"
                $gptTmpl = Join-Path $secEditDir "GptTmpl.inf"
                
                # Create directory structure
                if (-not (Test-Path $secEditDir)) {
                    New-Item -ItemType Directory -Path $secEditDir -Force -ErrorAction SilentlyContinue | Out-Null
                }
                
                # Create GptTmpl.inf with dangerous user rights
                $gptTmplContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeServiceLogonRight = *S-1-5-20,$userSID
SeDebugPrivilege = *S-1-5-20,$userSID
SeTakeOwnershipPrivilege = *S-1-5-20,$userSID
"@
                
                $gptTmplContent | Out-File -FilePath $gptTmpl -Force -Encoding ASCII -ErrorAction SilentlyContinue
                Write-Log "    [+] Created GptTmpl.inf with dangerous user rights for $($testUser.SamAccountName)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error setting user rights: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 6: IOE #4: Dangerous GPO logon script path
        # =====================================================================
        
        Write-Log "PHASE 6: Configure dangerous logon script path" -Level INFO
        Write-Log "  [*] IOE: Dangerous GPO logon script path (script exists, writable)" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                # Get local SYSVOL path (must use local path, not UNC)
                $gpoGUID = $rightGPO.Id.ToString().ToUpper()
                $gpoGUID = "{" + $gpoGUID + "}"
                $sysvolPath = "C:\Windows\SYSVOL\sysvol\$domainFQDN\Policies\$gpoGUID\User\Scripts\Logon"
                $scriptsDir = "C:\Windows\SYSVOL\sysvol\$domainFQDN\Policies\$gpoGUID\User\Scripts"
                
                # Create directory structure
                if (-not (Test-Path $sysvolPath)) {
                    New-Item -ItemType Directory -Path $sysvolPath -Force -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "    [+] Created SYSVOL logon script directory" -Level SUCCESS
                }
                
                # Create the actual logon script file
                $scriptFile = "breakAD.bat"
                $scriptPath = Join-Path $sysvolPath $scriptFile
                "@echo off`nREM breakAD logon script" | Out-File -FilePath $scriptPath -Force -Encoding ASCII -ErrorAction SilentlyContinue
                Write-Log "    [+] Created logon script file: $scriptPath" -Level SUCCESS
                
                # Set permissive ACLs on the script file (allow Everyone to modify)
                try {
                    $acl = Get-Acl $scriptPath
                    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        "Everyone",
                        "Modify",
                        "Allow"
                    )
                    $acl.AddAccessRule($accessRule)
                    Set-Acl -Path $scriptPath -AclObject $acl -ErrorAction SilentlyContinue
                    Write-Log "    [+] Set permissive ACLs on logon script (Everyone can modify)" -Level SUCCESS
                }
                catch {
                    Write-Log "    [!] Error setting ACLs on script: $_" -Level WARNING
                }
                
                # Create Scripts.ini to register the logon script in GPO
                $scriptsIni = Join-Path $scriptsDir "Scripts.ini"
                $scriptIniContent = @"
[Logon]
0CmdLine=$scriptFile
0Parameters=
"@
                $scriptIniContent | Out-File -FilePath $scriptsIni -Force -Encoding ASCII -ErrorAction SilentlyContinue
                Write-Log "    [+] Created Scripts.ini with logon script reference" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error setting logon script: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        

        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 8: IOE #11: GPO weak LM hash storage enabled
        # =====================================================================
        
        Write-Log "PHASE 8: Enable weak LM hash storage in GPO" -Level INFO
        Write-Log "  [*] IOE: GPO weak LM hash storage enabled" -Level INFO
        
        try {
            $rightGPO = Get-GPO -Name "breakAD-LinkTest-OU" -ErrorAction SilentlyContinue
            
            if ($rightGPO) {
                # Update GptTmpl.inf to disable NoLMHash (enable weak LM hash)
                $gpoGUID = $rightGPO.Id.ToString().ToUpper()
                $gpoGUID = "{" + $gpoGUID + "}"
                $gptTmpl = "C:\Windows\SYSVOL\sysvol\$domainFQDN\Policies\$gpoGUID\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                
                if (Test-Path $gptTmpl) {
                    $content = Get-Content $gptTmpl -Raw
                    
                    # Add Registry Values section if not present
                    if ($content -notmatch "\[Registry Values\]") {
                        $content += "`n[Registry Values]`n"
                    }
                    
                    # Add NoLMHash setting (4 = DWORD, 0 = disabled)
                    if ($content -notmatch "NoLMHash") {
                        $content = $content -replace "(\[Registry Values\])", "`$1`nMACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,0"
                    }
                    else {
                        # Replace existing NoLMHash setting
                        $content = $content -replace "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=.*", "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,0"
                    }
                    
                    $content | Out-File -FilePath $gptTmpl -Force -Encoding ASCII -ErrorAction SilentlyContinue
                    Write-Log "    [+] Added NoLMHash=0 to GptTmpl.inf" -Level SUCCESS
                }
            }
        }
        catch {
            Write-Log "    [!] Error setting LM hash: $_" -Level WARNING
        }

        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 11: IOE #6, #7, #8: GPO linking delegation
        # =====================================================================
        
        Write-Log "PHASE 11: Grant GPO linking delegation" -Level INFO
        Write-Log "  [*] IOE: GPO linking delegation at domain/site/OU levels" -Level INFO
        
        try {
            # Create a lab user for delegation if not exists
            $delUser = Get-ADUser -Filter { SamAccountName -eq "break-gpo-delegate" } -ErrorAction SilentlyContinue
            
            if (-not $delUser) {
                $delUser = New-ADUser -Name "break-gpo-delegate" `
                    -SamAccountName "break-gpo-delegate" `
                    -UserPrincipalName "break-gpo-delegate@$domainFQDN" `
                    -Path "OU=Users,OU=BreakAD,$domainDN" `
                    -AccountPassword (ConvertTo-SecureString -AsPlainText "TempPassword123!" -Force) `
                    -Enabled $true `
                    -ErrorAction Stop -PassThru
                
                Write-Log "    [+] Created delegation user: break-gpo-delegate" -Level SUCCESS
            }
            else {
                Write-Log "    [*] Delegation user already exists" -Level INFO
            }
            
            $linkGPOGUID = [System.Guid]"01814787-5BB5-42d3-A4D5-0595BC1DD92A"  # LinkGPO control right
            $sid = New-Object System.Security.Principal.SecurityIdentifier($delUser.SID)
            
            # IOE #8: Delegation on domain object (domain level)
            Write-Log "    Granting delegation at domain level..." -Level INFO
            try {
                $acl = Get-Acl "AD:$domainDN"
                
                # Grant LinkGPO control right
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $linkGPOGUID
                )
                $acl.AddAccessRule($ace)
                
                # Also grant WriteProperty on gPLink attribute specifically
                $gPLinkGUID = [System.Guid]"f30e3bbe-9ff0-11d1-b603-0000f80367c1"  # gPLink attribute
                $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $gPLinkGUID
                )
                $acl.AddAccessRule($ace2)
                
                Set-Acl "AD:$domainDN" $acl -ErrorAction Stop
                Write-Log "      [+] Granted GPO linking delegation on domain object" -Level SUCCESS
            }
            catch {
                Write-Log "      [!] Error granting domain-level delegation: $_" -Level WARNING
            }
            
            # IOE #6: Delegation on Site object (site level)
            Write-Log "    Granting delegation at Site level..." -Level INFO
            try {
                $siteDN = Get-ADObject -Filter { ObjectClass -eq "site" } `
                    -SearchBase "CN=Sites,CN=Configuration,$domainDN" `
                    -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty DistinguishedName
                
                if ($siteDN) {
                    $acl = Get-Acl "AD:$siteDN"
                    
                    # Grant WriteDACL on site object
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sid,
                        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
                        [System.Security.AccessControl.AccessControlType]::Allow
                    )
                    $acl.AddAccessRule($ace)
                    Set-Acl "AD:$siteDN" $acl -ErrorAction Stop
                    Write-Log "      [+] Granted WriteDACL on Site: $siteDN" -Level SUCCESS
                }
                else {
                    Write-Log "      [!] No sites found for site-level delegation" -Level WARNING
                }
            }
            catch {
                Write-Log "      [!] Error granting site-level delegation: $_" -Level WARNING
            }
            
            # IOE #7: Delegation on Domain Controllers OU
            Write-Log "    Granting delegation at DC OU level..." -Level INFO
            try {
                $dcOU = Get-ADOrganizationalUnit -Filter { Name -eq "Domain Controllers" } -ErrorAction SilentlyContinue
                
                if ($dcOU) {
                    $acl = Get-Acl "AD:$($dcOU.DistinguishedName)"
                    
                    # Grant LinkGPO control right
                    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sid,
                        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $linkGPOGUID
                    )
                    $acl.AddAccessRule($ace)
                    
                    # Also grant WriteProperty on gPLink attribute specifically
                    $gPLinkGUID = [System.Guid]"f30e3bbe-9ff0-11d1-b603-0000f80367c1"  # gPLink attribute
                    $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        $sid,
                        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                        [System.Security.AccessControl.AccessControlType]::Allow,
                        $gPLinkGUID
                    )
                    $acl.AddAccessRule($ace2)
                    
                    Set-Acl "AD:$($dcOU.DistinguishedName)" $acl -ErrorAction Stop
                    Write-Log "      [+] Granted GPO linking delegation on Domain Controllers OU" -Level SUCCESS
                }
                else {
                    Write-Log "      [!] Domain Controllers OU not found" -Level WARNING
                }
            }
            catch {
                Write-Log "      [!] Error granting DC OU delegation: $_" -Level WARNING
            }
        }
        catch {
            Write-Log "    [!] Error in delegation phase: $_" -Level WARNING
        }
        
        Write-Log "" -Level INFO
        
        # =====================================================================
        # PHASE 12: Force Group Policy update
        # =====================================================================
        
        Write-Log "PHASE 12: Force Group Policy update" -Level INFO
        
        try {
            Invoke-Command -ComputerName $dcFQDN -ScriptBlock {
                gpupdate /force /wait:0
            } -ErrorAction SilentlyContinue | Out-Null
            
            Write-Log "  [+] Group Policy update forced" -Level SUCCESS

        
        Write-Log "" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "Module 01: Group Policy Security - COMPLETE" -Level INFO
        Write-Log "========================================" -Level INFO
        Write-Log "" -Level INFO
        
        return $true
    }
    catch {
        Write-Log "Module 01 Error: $_" -Level ERROR
        return $false
    }
}

Export-ModuleMember -Function Invoke-ModuleGroupPolicySecurity